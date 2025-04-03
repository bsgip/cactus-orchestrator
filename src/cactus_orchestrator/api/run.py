import logging
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from typing import Annotated

import shortuuid
from cactus_runner.client import ClientSession, RunnerClient, RunnerClientException
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi_async_sqlalchemy import db
from fastapi_pagination import Page, paginate
from sqlalchemy.exc import NoResultFound
from sqlalchemy.ext.asyncio import AsyncSession

from cactus_orchestrator.auth import AuthScopes, jwt_validator
from cactus_orchestrator.crud import (
    create_runartifact,
    insert_run_for_user,
    select_user,
    select_user_run,
    select_user_run_with_artifact,
    select_user_runs,
    update_run_with_runartifact_and_finalise,
)
from cactus_orchestrator.k8s.resource import get_resource_names
from cactus_orchestrator.k8s.resource.create import add_ingress_rule, clone_service, clone_statefulset, wait_for_pod
from cactus_orchestrator.k8s.resource.delete import delete_service, delete_statefulset, remove_ingress_rule
from cactus_orchestrator.model import FinalisationStatus, Run, RunArtifact, User
from cactus_orchestrator.schema import RunResponse, StartRunRequest, StartRunResponse, UserContext
from cactus_orchestrator.settings import (
    CLONED_RESOURCE_NAME_FORMAT,
    POD_HARNESS_RUNNER_MANAGEMENT_PORT,
    RUNNER_POD_URL,
    TEST_EXECUTION_URL_FORMAT,
    CactusOrchestratorException,
    main_settings,
)

logger = logging.getLogger(__name__)


router = APIRouter()


def map_run_to_run_response(run: Run) -> RunResponse:
    svc_name = CLONED_RESOURCE_NAME_FORMAT.format(
        resource_name=main_settings.template_service_name, uuid=run.teststack_id
    )
    return RunResponse(
        run_id=run.run_id,
        test_procedure_id=run.testprocedure_id,
        test_url=TEST_EXECUTION_URL_FORMAT.format(fqdn=main_settings.test_execution_fqdn, svc_name=svc_name),
        finalised=(
            True if run.finalisation_status in (FinalisationStatus.by_client, FinalisationStatus.by_timeout) else False
        ),
    )


async def select_user_or_raise(
    session: AsyncSession, user_context: UserContext, with_der: bool = False, with_p12: bool = False
) -> User:
    user = await select_user(session, user_context, with_der, with_p12)

    if user is None:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Certificate has not been registered.")
    return user


@router.get("/run", status_code=HTTPStatus.OK)
async def get_runs_paginated(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
    finalised: bool = Query(default=True),
    created_after: datetime = Query(default=datetime.now(tz=timezone.utc) - timedelta(days=7)),
) -> Page[RunResponse]:
    # get user
    user = await select_user_or_raise(db.session, user_context)

    # get runs
    runs = await select_user_runs(db.session, user.user_id, finalised=finalised, created_at_gte=created_after)

    if runs:
        resp = [map_run_to_run_response(run) for run in runs if run]
    else:
        resp = []
    return paginate(resp)


@router.post(
    "/run",
    status_code=HTTPStatus.CREATED,
    responses={
        HTTPStatus.CREATED: {"headers": {"Location": {"description": "URL of the newly created test server resource."}}}
    },
)
async def spawn_teststack_and_start_run(
    test: StartRunRequest,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
    response: Response,
) -> StartRunResponse:
    """This endpoint sets up a test procedure as requested by client.
    Steps are:
        (1) Create a service/statefulset representing the isolated envoy test environment.
        (2) Init any state in the envoy environment.
        (3) Update the ingress with a path to the envoy environment.
    """
    # get user
    user = await select_user_or_raise(db.session, user_context, with_der=True)

    client_cert = x509.load_der_x509_certificate(user.certificate_x509_der)

    if client_cert.not_valid_after_utc < datetime.now(timezone.utc):
        raise HTTPException(
            HTTPStatus.CONFLICT,
            detail="Your certificate has expired. Please regenerate your certificate and try again.",
        )

    # new resource ids
    teststack_id: str = shortuuid.uuid().lower()  # This uuid is referenced in all new resource ids
    new_svc_name, new_statefulset_name, new_app_label, pod_name, pod_fqdn = get_resource_names(teststack_id)
    try:
        # duplicate resources
        await clone_statefulset(new_statefulset_name, new_svc_name, new_app_label)
        await clone_service(new_svc_name, new_app_label)

        # wait for statefulset's pod
        await wait_for_pod(pod_name)

        # inject initial state
        runner_session = ClientSession(
            RUNNER_POD_URL.format(pod_fqdn=pod_fqdn, pod_port=POD_HARNESS_RUNNER_MANAGEMENT_PORT)
        )
        await RunnerClient.start(
            runner_session, test.test_procedure_id, client_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        )

        # finally, include new service in ingress rule
        await add_ingress_rule(new_svc_name)

    except (CactusOrchestratorException, RunnerClientException) as exc:
        logger.info(exc)
        await teardown_teststack(new_svc_name, new_statefulset_name)
        raise HTTPException(HTTPStatus.INTERNAL_SERVER_ERROR, detail="Internal Server Error")

    # track in DB
    run_id = await insert_run_for_user(db.session, user.user_id, teststack_id, test.test_procedure_id)
    await db.session.commit()

    # set location header
    response.headers["Location"] = TEST_EXECUTION_URL_FORMAT.format(
        fqdn=main_settings.test_execution_fqdn, svc_name=new_svc_name
    )

    return StartRunResponse(
        run_id=run_id,
    )


async def teardown_teststack(svc_name: str, statefulset_name: str) -> None:
    """Tears down the envoy teststack (ingress rule + service + statefulset)"""
    # Remove ingress rule
    await remove_ingress_rule(svc_name)

    # Remove resources
    await delete_service(svc_name)
    await delete_statefulset(statefulset_name)


async def finalise_run(
    run: Run, url: str, session: AsyncSession, finalisation_status: FinalisationStatus, finalised_at: datetime
) -> RunArtifact:
    runner_session = ClientSession(url)

    # NOTE: we are assuming that files are small, consider streaming to file store
    # if sizes increase.
    file_data = (await RunnerClient.finalize(runner_session)).encode(
        "utf-8"
    )  # TODO: this should return bytes, encoding for now
    compression = "zip"  # TODO: should also return compression or allow access to response header

    artifact = await create_runartifact(session, compression, file_data)
    await update_run_with_runartifact_and_finalise(
        session, run, artifact.run_artifact_id, finalisation_status, finalised_at
    )

    return artifact


@router.post("/run/{run_id}/finalise", status_code=HTTPStatus.OK)
async def finalise_run_and_teardown_teststack(
    run_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
) -> Response:
    # get user
    user = await select_user_or_raise(db.session, user_context)

    # get run
    try:
        run = await select_user_run(db.session, user.user_id, run_id)
    except NoResultFound as exc:
        logger.debug(exc)
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Not Found")

    # get resource names
    svc_name, statefulset_name, _, _, pod_fqdn = get_resource_names(run.teststack_id)
    pod_url = RUNNER_POD_URL.format(pod_fqdn=pod_fqdn, pod_port=POD_HARNESS_RUNNER_MANAGEMENT_PORT)

    # finalise
    artifact = await finalise_run(run, pod_url, db.session, FinalisationStatus.by_client, datetime.now(timezone.utc))
    await db.session.commit()

    # teardown
    await teardown_teststack(svc_name=svc_name, statefulset_name=statefulset_name)

    return Response(
        content=artifact.file_data,
        media_type=f"application/{artifact.compression}",
    )


@router.get("/run/{run_id}/artifact", status_code=HTTPStatus.OK)
async def get_run_artifact(
    run_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
) -> Response:

    # get user
    user = await select_user_or_raise(db.session, user_context)

    # get run
    try:
        run = await select_user_run_with_artifact(db.session, user.user_id, run_id)
    except NoResultFound as exc:
        logger.debug(exc)
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Not Found")

    return Response(
        content=run.run_artifact.file_data,
        media_type=f"application/{run.run_artifact.compression}",
    )
