import logging
from http import HTTPStatus
from typing import Annotated

from cactus_schema.orchestrator import RunGroupRequest, RunGroupResponse, RunGroupUpdateRequest, uri
from cactus_test_definitions import CSIPAusVersion
from fastapi import APIRouter, Depends, HTTPException
from fastapi_async_sqlalchemy import db
from fastapi_pagination import Page, paginate

from cactus_orchestrator.api.common import select_user_or_raise, select_user_run_group_or_raise
from cactus_orchestrator.api.run import prepare_run_for_delete
from cactus_orchestrator.auth import AuthPerm, UserContext, jwt_validator
from cactus_orchestrator.crud import (
    delete_runs,
    insert_run_group,
    select_run_group_counts_for_user,
    select_run_groups_for_user,
    select_runs_for_group,
)
from cactus_orchestrator.model import RunGroup

logger = logging.getLogger(__name__)


router = APIRouter()


def map_group_to_group_response(group: RunGroup, total_runs: int) -> RunGroupResponse:
    return RunGroupResponse(
        run_group_id=group.run_group_id,
        name=group.name,
        csip_aus_version=group.csip_aus_version,
        created_at=group.created_at,
        total_runs=total_runs,
        certificate_id=group.certificate_id,
        certificate_created_at=group.certificate_generated_at,
        is_device_cert=group.is_device_cert,
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

    if run_groups:
        resp = [
            map_group_to_group_response(group, run_group_counts.get(group.run_group_id, 0))
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
    except Exception:
        raise HTTPException(
            HTTPStatus.BAD_REQUEST, detail=f"'{group_request.csip_aus_version}' doesn't map to a known CSIPAusVersion"
        )

    # get runs
    run_group = await insert_run_group(db.session, user.user_id, csip_aus_version.value)
    await db.session.commit()
    return map_group_to_group_response(run_group, 0)


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

    # get runs
    await db.session.commit()
    return map_group_to_group_response(run_group, 0)


@router.delete(uri.RunGroup, status_code=HTTPStatus.NO_CONTENT)
async def delete_group(
    run_group_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
) -> None:

    # get group
    _, run_group = await select_user_run_group_or_raise(db.session, user_context, run_group_id)

    # Close out any existing k8s resources for runs before deletion
    all_runs = await select_runs_for_group(db.session, run_group_id, finalised=None, created_at_gte=None)
    for run in all_runs:
        await prepare_run_for_delete(run)

    # Delete the runs + groups
    await delete_runs(db.session, all_runs)
    await db.session.delete(run_group)

    await db.session.commit()
