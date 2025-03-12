import base64
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
import shortuuid
from cryptography.hazmat.primitives import serialization

from cactus.harness_orchestrator.k8s_management.certificate.create import generate_client_p12
from cactus.harness_orchestrator.k8s_management.certificate.fetch import (
    fetch_certificate_key_pair,
)
from cactus.harness_orchestrator.runner_client import HarnessRunnerAsyncClient, StartTestRequest
from cactus.harness_orchestrator.schema import SpawnTestRequest, SpawnTestResponse
from cactus.harness_orchestrator.k8s_management.resource import (
    add_ingress_rule,
    clone_service,
    clone_statefulset,
    wait_for_pod,
)
from cactus.harness_orchestrator.settings import (
    CLONED_RESOURCE_NAME_FORMAT,
    POD_HARNESS_RUNNER_MANAGEMENT_PORT,
    TEST_CLIENT_P12_PASSWORD,
    TESTING_URL_FORMAT,
    POD_FQDN_FORMAT,
    main_settings,
)


app = FastAPI()


# NOTE: Client cert generation could potentially be part of user sign-up process instead.
# I suspect a new one per test will be onerous.
@app.post("/spawn-test", status_code=201)
async def spawn_test(test: SpawnTestRequest) -> SpawnTestResponse:
    """This endpoint setups a test procedure as requested by client.
    Steps are:
        (1) Create a service/statefulset representing the isolated envoy test environment.
        (2) Create a fresh client certificate signed by the CA cert/key in the K8s secret store.
        (3) Init any state in the envoy environment.
        (4) Update the ingress with a path to the envoy environment.
    """
    # new resource ids
    uuid: str = shortuuid.uuid().lower()  # This uuid is referenced in all new resource ids
    new_svc_name = CLONED_RESOURCE_NAME_FORMAT.format(resource_name=main_settings.template_service_name, uuid=uuid)
    new_app_label = CLONED_RESOURCE_NAME_FORMAT.format(resource_name=main_settings.template_app_name, uuid=uuid)
    new_statefulset_name = CLONED_RESOURCE_NAME_FORMAT.format(resource_name=main_settings.template_app_name, uuid=uuid)

    # duplicate resources
    clone_service(new_svc_name, new_app_label)
    pod_name = clone_statefulset(new_statefulset_name, new_svc_name, new_app_label)
    pod_fqdn = POD_FQDN_FORMAT.format(
        pod_name=pod_name, svc_name=new_svc_name, namespace=main_settings.testing_namespace
    )

    # wait for statefulset's pod
    await wait_for_pod(pod_name)

    # create client certificate
    ca_cert, ca_key = fetch_certificate_key_pair(main_settings.tls_ca_tls_secret_name)
    client_p12, client_cert = generate_client_p12(
        ca_cert=ca_cert, ca_key=ca_key, client_common_name=uuid, p12_password=TEST_CLIENT_P12_PASSWORD
    )

    # inject initial state
    run_cl = HarnessRunnerAsyncClient(pod_fqdn, POD_HARNESS_RUNNER_MANAGEMENT_PORT)
    success = await run_cl.post_start_test(
        test_code=test.code,
        body=StartTestRequest(client_cert=client_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")),
    )

    if not success:
        raise HTTPException(404, "Failed to spawn test.")

    # finally, include new service in ingress rule
    add_ingress_rule(new_svc_name)

    return SpawnTestResponse(
        ca_cert=ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        client_p12=base64.b64encode(client_p12).decode("utf-8"),
        p12_password=TEST_CLIENT_P12_PASSWORD,
        test_url=TESTING_URL_FORMAT.format(testing_fqdn=main_settings.testing_fqdn, svc_name=new_svc_name),
    )
