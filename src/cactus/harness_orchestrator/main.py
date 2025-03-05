from fastapi import FastAPI
import shortuuid
from cryptography.hazmat.primitives import serialization

from cactus.harness_orchestrator.k8s_management.certificate.create import generate_client_p12
from cactus.harness_orchestrator.k8s_management.certificate.fetch import (
    fetch_certificate_key_pair,
)
from cactus.harness_orchestrator.schema import StartTestRequest, StartTestResponse
from cactus.harness_orchestrator.k8s_management.resource import (
    add_ingress_rule,
    clone_service,
    clone_statefulset,
    wait_for_pod,
)
from cactus.harness_orchestrator.settings import (
    CLONED_RESOURCE_NAME_FORMAT,
    TEST_CLIENT_P12_PASSWORD,
    main_settings,
)


app = FastAPI()


# NOTE: Client cert generation could potentially be part of user sign-up process instead.
# I suspect a new one per test will be onerous.
@app.post("/start-test", status_code=201)
async def start_test(test: StartTestRequest) -> StartTestResponse:
    """This endpoint setups a test procedure as requested by client.
    Steps are:
        (1) Create a service/statefulset representing the isolated envoy test environment.
        (2) Create a fresh client certificate signed by the CA cert/key in the K8s secret store.
        (3) Init any state in the envoy environment.
        (4) Update the ingress with a path to the envoy environment.
    """
    # new resource ids
    uuid: str = shortuuid.uuid().lower()  # This uuid is referenced in all new resource ids
    new_service_name = CLONED_RESOURCE_NAME_FORMAT.format(resource_id=main_settings.template_service_name, uuid=uuid)
    new_app_label = CLONED_RESOURCE_NAME_FORMAT.format(resource_id=main_settings.template_app_name, uuid=uuid)
    new_statefulset_name = CLONED_RESOURCE_NAME_FORMAT.format(resource_id=main_settings.template_app_name, uuid=uuid)

    # duplicate resources
    clone_service(main_settings.template_statefulset_name, new_service_name, new_app_label)
    pod_name = clone_statefulset(new_statefulset_name, new_service_name, new_app_label)

    # wait for statefulset's pod
    await wait_for_pod(pod_name)

    # create client certificate

    ca_cert, ca_key = fetch_certificate_key_pair(main_settings.tls_ca_tls_secret_name)

    # inject initial state
    client_p12 = generate_client_p12(
        ca_cert=ca_key, ca_key=ca_key, client_common_name=uuid, p12_password=TEST_CLIENT_P12_PASSWORD
    )  # TODO

    # finally, include new service in ingress rule
    add_ingress_rule(new_service_name)

    return StartTestResponse(
        ca_cert=ca_cert.public_bytes(serialization.Encoding.PEM),
        client_p12=client_p12,
        p12_password=TEST_CLIENT_P12_PASSWORD,
    )
