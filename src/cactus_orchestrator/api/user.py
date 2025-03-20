import base64
from datetime import datetime, timezone
import logging
from http import HTTPStatus
from typing import Annotated

from fastapi import HTTPException, APIRouter, Depends
import shortuuid
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi_async_sqlalchemy import db
from sqlalchemy.exc import IntegrityError

from cactus_orchestrator.api.crud import add_or_update_user, add_user, get_user_certificate_x509_der
from cactus_orchestrator.k8s.certificate.create import generate_client_p12
from cactus_orchestrator.k8s.certificate.fetch import fetch_certificate_key_pair
from cactus_orchestrator.k8s.resource import get_resource_names
from cactus_orchestrator.runner_client import HarnessRunnerAsyncClient, RunnerClientException, StartTestRequest
from cactus_orchestrator.schema import (
    SpawnTestRequest,
    SpawnTestResponse,
    UserContext,
    UserResponse,
)
from cactus_orchestrator.k8s.resource.create import (
    add_ingress_rule,
    clone_service,
    clone_statefulset,
    wait_for_pod,
)
from cactus_orchestrator.k8s.resource.delete import (
    remove_ingress_rule,
    delete_service,
    delete_statefulset,
)
from cactus_orchestrator.settings import (
    POD_HARNESS_RUNNER_MANAGEMENT_PORT,
    TEST_CLIENT_P12_PASSWORD,
    TESTING_URL_FORMAT,
    HarnessOrchestratorException,
    main_settings,
)
from cactus_orchestrator.auth import jwt_validator, AuthScopes


logger = logging.getLogger(__name__)


router = APIRouter()


def create_client_cert_binary(user_context: UserContext) -> tuple[bytes, bytes]:
    # create client certificate
    ca_cert, ca_key = fetch_certificate_key_pair(main_settings.tls_ca_tls_secret_name)
    client_p12, client_cert = generate_client_p12(
        ca_cert=ca_cert,
        ca_key=ca_key,
        client_common_name=user_context.subject_id,
        p12_password=TEST_CLIENT_P12_PASSWORD.get_secret_value(),
    )
    return client_p12, client_cert.public_bytes(encoding=serialization.Encoding.DER)


# NOTE: Client cert generation could potentially be part of user sign-up process instead.
# I suspect a new one per test will be onerous.
# TODO: Returning uuid for now, will swap to table sequence pkey later.
@router.post("/run", status_code=HTTPStatus.CREATED)
async def spawn_teststack(
    test: SpawnTestRequest,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
) -> SpawnTestResponse:
    """This endpoint setups a test procedure as requested by client.
    Steps are:
        (1) Create a service/statefulset representing the isolated envoy test environment.
        (2) Init any state in the envoy environment.
        (3) Update the ingress with a path to the envoy environment.
    """
    # get client cert
    certificate_x509_der = await get_user_certificate_x509_der(db.session, user_context)

    # TODO: make more robust
    if certificate_x509_der is None:
        raise HTTPException(HTTPStatus.CONFLICT, detail="User has not been registered. Register user and try again.")

    client_cert = x509.load_der_x509_certificate(certificate_x509_der)

    if client_cert.not_valid_after_utc < datetime.now(timezone.utc):
        raise HTTPException(
            HTTPStatus.CONFLICT,
            detail="Your certificate has expired. Please regenerate your certificate and try again.",
        )

    # new resource ids
    uuid: str = shortuuid.uuid().lower()  # This uuid is referenced in all new resource ids
    new_svc_name, new_statefulset_name, new_app_label, pod_name, pod_fqdn = get_resource_names(uuid)
    try:
        # duplicate resources
        await clone_statefulset(new_statefulset_name, new_svc_name, new_app_label)
        await clone_service(new_svc_name, new_app_label)

        # wait for statefulset's pod
        await wait_for_pod(pod_name)

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


@router.post("/user", status_code=HTTPStatus.CREATED)
async def create_new_user(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
) -> UserResponse:
    # create certs
    client_p12, client_x509_der = create_client_cert_binary(user_context)

    try:
        # write user
        _ = await add_user(db.session, user_context, client_p12, client_x509_der)
    except IntegrityError as exc:
        logger.debug(exc)
        raise HTTPException(status_code=HTTPStatus.CONFLICT, detail="user exists.")

    return UserResponse(
        certificate_p12_b64=base64.b64encode(client_p12).decode("utf-8"),
        password=TEST_CLIENT_P12_PASSWORD,
    )


@router.patch("/user", status_code=HTTPStatus.CREATED)
async def update_existing_user_certificate(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
) -> UserResponse:
    # create certs
    client_p12, client_x509_der = create_client_cert_binary(user_context)

    _ = await add_or_update_user(db.session, user_context, client_p12, client_x509_der)

    return UserResponse(
        certificate_p12_b64=base64.b64encode(client_p12).decode("utf-8"),
        password=TEST_CLIENT_P12_PASSWORD,
    )
