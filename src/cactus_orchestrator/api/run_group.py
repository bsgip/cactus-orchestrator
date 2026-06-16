import logging
from http import HTTPStatus
from typing import Annotated

from cactus_schema.orchestrator import RunGroupRequest, RunGroupResponse, RunGroupUpdateRequest, uri
from cactus_test_definitions import CSIPAusVersion
from fastapi import APIRouter, Depends, HTTPException
from fastapi_async_sqlalchemy import db
from fastapi_pagination import Page, paginate

from cactus_orchestrator.api.common import envoy_dcap_uri_for_host, select_user_or_raise, select_user_run_group_or_raise
from cactus_orchestrator.auth import AuthPerm, UserContext, jwt_validator
from cactus_orchestrator.crud import (
    ACTIVE_RUN_STATUSES,
    delete_runs,
    insert_run_group,
    select_run_group_counts_for_user,
    select_run_groups_for_user,
    select_runs_for_group,
)
from cactus_orchestrator.model import RunGroup
from cactus_orchestrator.pod.manager import destroy_pod_resources
from cactus_orchestrator.pod.models import ENVOY_HREF_PREFIX, PodResources, generate_static_uri_external_host
from cactus_orchestrator.settings import get_current_settings

logger = logging.getLogger(__name__)


router = APIRouter()


def map_group_to_group_response(group: RunGroup, test_execution_fqdn: str, total_runs: int) -> RunGroupResponse:
    if group.is_static_uri:
        static_uri = envoy_dcap_uri_for_host(
            generate_static_uri_external_host(test_execution_fqdn, group.run_group_id), ENVOY_HREF_PREFIX
        )
    else:
        static_uri = None
    return RunGroupResponse(
        run_group_id=group.run_group_id,
        name=group.name,
        csip_aus_version=group.csip_aus_version,
        created_at=group.created_at,
        total_runs=total_runs,
        certificate_id=group.certificate_id,
        certificate_created_at=group.certificate_generated_at,
        is_device_cert=group.is_device_cert,
        is_static_uri=group.is_static_uri,
        static_uri=static_uri,
    )


@router.get(uri.RunGroupList, status_code=HTTPStatus.OK)
async def get_groups_paginated(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
) -> Page[RunGroupResponse]:
    # get user
    user = await select_user_or_raise(db.session, user_context)

    # get runs
    run_groups = await select_run_groups_for_user(db.session, user.user_id)
    run_group_counts = await select_run_group_counts_for_user(db.session, [r.run_group_id for r in run_groups])

    settings = get_current_settings()
    if run_groups:
        resp = [
            map_group_to_group_response(
                group, settings.test_execution_fqdn, run_group_counts.get(group.run_group_id, 0)
            )
            for group in run_groups
            if group
        ]
    else:
        resp = []
    return paginate(resp)


@router.post(uri.RunGroupList, status_code=HTTPStatus.CREATED)
async def create_group(
    group_request: RunGroupRequest,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
) -> RunGroupResponse:

    # get user
    user = await select_user_or_raise(db.session, user_context)

    try:
        csip_aus_version = CSIPAusVersion(group_request.csip_aus_version)
    except Exception as err:
        raise HTTPException(
            HTTPStatus.BAD_REQUEST, detail=f"'{group_request.csip_aus_version}' doesn't map to a known CSIPAusVersion"
        ) from err

    # get runs
    run_group = await insert_run_group(db.session, user.user_id, csip_aus_version.value, group_request.is_static_uri)
    await db.session.commit()

    settings = get_current_settings()
    return map_group_to_group_response(run_group, settings.test_execution_fqdn, 0)


@router.put(uri.RunGroup, status_code=HTTPStatus.OK)
async def update_group(
    run_group_id: int,
    group_request: RunGroupUpdateRequest,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
) -> RunGroupResponse:

    # get user
    _, run_group = await select_user_run_group_or_raise(db.session, user_context, run_group_id)

    if group_request.name:
        run_group.name = group_request.name
    run_group.is_static_uri = group_request.is_static_uri

    # get runs
    await db.session.commit()

    settings = get_current_settings()
    return map_group_to_group_response(run_group, settings.test_execution_fqdn, 0)


@router.delete(uri.RunGroup, status_code=HTTPStatus.NO_CONTENT)
async def delete_group(
    run_group_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
) -> None:

    # get group
    _, run_group = await select_user_run_group_or_raise(db.session, user_context, run_group_id)

    settings = get_current_settings()

    # Close out any existing pod resources for runs before deletion
    all_runs = await select_runs_for_group(db.session, run_group_id, finalised=None, created_at_gte=None)
    for run in all_runs:
        if run.run_status in ACTIVE_RUN_STATUSES:
            pod_resources = PodResources.from_run(settings.podman_network, run)
            await destroy_pod_resources(settings.podman_socket, pod_resources)

    # Delete the runs + groups
    await delete_runs(db.session, all_runs)
    await db.session.delete(run_group)

    await db.session.commit()
