import logging
from datetime import datetime, timezone
from http import HTTPStatus
from typing import Annotated

import shortuuid
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, HTTPException
from fastapi_async_sqlalchemy import db

from cactus_orchestrator.auth import AuthScopes, jwt_validator
from cactus_orchestrator.crud import select_user_certificate_x509_der
from cactus_orchestrator.k8s.resource import get_resource_names
from cactus_orchestrator.k8s.resource.create import add_ingress_rule, clone_service, clone_statefulset, wait_for_pod
from cactus_orchestrator.k8s.resource.delete import delete_service, delete_statefulset, remove_ingress_rule
from cactus_orchestrator.runner_client import HarnessRunnerAsyncClient, RunnerClientException, StartTestRequest
from cactus_orchestrator.schema import SpawnTestRequest, SpawnTestResponse, UserContext
from cactus_orchestrator.settings import (
    POD_HARNESS_RUNNER_MANAGEMENT_PORT,
    TESTING_URL_FORMAT,
    HarnessOrchestratorException,
    main_settings,
)

logger = logging.getLogger(__name__)


router = APIRouter()


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
    certificate_x509_der = await select_user_certificate_x509_der(db.session, user_context)

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
