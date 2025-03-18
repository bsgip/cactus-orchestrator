import logging
import base64
from http import HTTPStatus

from fastapi import HTTPException, APIRouter, Depends
import shortuuid
from cryptography.hazmat.primitives import serialization

from cactus.harness_orchestrator.k8s_management.certificate.create import generate_client_p12
from cactus.harness_orchestrator.k8s_management.certificate.fetch import (
    fetch_certificate_key_pair,
)
from cactus.harness_orchestrator.k8s_management.resource import get_resource_names
from cactus.harness_orchestrator.runner_client import HarnessRunnerAsyncClient, RunnerClientException, StartTestRequest
from cactus.harness_orchestrator.schema import FinalizeTestResponse, SpawnTestRequest, SpawnTestResponse
from cactus.harness_orchestrator.k8s_management.resource.create import (
    add_ingress_rule,
    clone_service,
    clone_statefulset,
    wait_for_pod,
)
from cactus.harness_orchestrator.k8s_management.resource.delete import (
    remove_ingress_rule,
    delete_service,
    delete_statefulset,
)
from cactus.harness_orchestrator.settings import (
    POD_HARNESS_RUNNER_MANAGEMENT_PORT,
    TEST_CLIENT_P12_PASSWORD,
    TESTING_URL_FORMAT,
    HarnessOrchestratorException,
    main_settings,
)


logger = logging.getLogger(__name__)


router = APIRouter()


# NOTE: Client cert generation could potentially be part of user sign-up process instead.
# I suspect a new one per test will be onerous.
# TODO: Returning uuid for now, will swap to table sequence pkey later.
@router.post("/run", status_code=HTTPStatus.CREATED)
async def spawn_teststack(test: SpawnTestRequest) -> SpawnTestResponse:
    """This endpoint setups a test procedure as requested by client.
    Steps are:
        (1) Create a service/statefulset representing the isolated envoy test environment.
        (2) Create a fresh client certificate signed by the CA cert/key in the K8s secret store.
        (3) Init any state in the envoy environment.
        (4) Update the ingress with a path to the envoy environment.
    """
    # new resource ids
    uuid: str = shortuuid.uuid().lower()  # This uuid is referenced in all new resource ids
    new_svc_name, new_statefulset_name, new_app_label, pod_name, pod_fqdn = get_resource_names(uuid)
    try:
        # duplicate resources
        await clone_statefulset(new_statefulset_name, new_svc_name, new_app_label)
        await clone_service(new_svc_name, new_app_label)

        # wait for statefulset's pod
        await wait_for_pod(pod_name)

        # create client certificate
        ca_cert, ca_key = fetch_certificate_key_pair(main_settings.tls_ca_tls_secret_name)
        client_p12, client_cert = generate_client_p12(
            ca_cert=ca_cert,
            ca_key=ca_key,
            client_common_name=uuid,
            p12_password=TEST_CLIENT_P12_PASSWORD.get_secret_value(),
        )

        # inject initial state
        run_cl = HarnessRunnerAsyncClient(pod_fqdn, POD_HARNESS_RUNNER_MANAGEMENT_PORT)
        await run_cl.post_start_test(
            test_code=test.code,
            body=StartTestRequest(client_cert=client_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")),
        )

        # finally, include new service in ingress rule
        await add_ingress_rule(new_svc_name)

    except (HarnessOrchestratorException, RunnerClientException) as exc:
        logger.debug(exc)
        await teardown_teststack(new_svc_name, new_statefulset_name)
        raise HTTPException(HTTPStatus.INTERNAL_SERVER_ERROR, detail="Internal Server Error.")

    return SpawnTestResponse(
        ca_cert=ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        client_p12=base64.b64encode(client_p12).decode("utf-8"),
        p12_password=TEST_CLIENT_P12_PASSWORD,
        test_url=TESTING_URL_FORMAT.format(testing_fqdn=main_settings.testing_fqdn, svc_name=new_svc_name),
        run_id=uuid,
    )


async def teardown_teststack(svc_name: str, statefulset_name: str) -> None:
    """Tears down the envoy teststack (ingress rule + service + statefulset)"""
    # Remove ingress rule
    await remove_ingress_rule(svc_name)

    # Remove resources
    await delete_service(svc_name)
    await delete_statefulset(statefulset_name)


@router.post("/run/{run_id}/finalize", status_code=HTTPStatus.OK)
async def finalize_test(run_id: str) -> FinalizeTestResponse:
    # TODO: what to actually return?
    # resource ids
    uuid: str = run_id.lower()
    svc_name, statefulset_name, _, _, pod_fqdn = get_resource_names(uuid)

    # extract summary from harness runner
    run_cl = HarnessRunnerAsyncClient(pod_fqdn, POD_HARNESS_RUNNER_MANAGEMENT_PORT)
    await run_cl.post_finalize_test()

    # teardown test stack
    await teardown_teststack(svc_name, statefulset_name)
    return FinalizeTestResponse()
