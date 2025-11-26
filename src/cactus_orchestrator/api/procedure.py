import logging
from http import HTTPStatus
from importlib import resources
from typing import Annotated

from cactus_test_definitions import CSIPAusVersion
from cactus_test_definitions.client import TestProcedure, TestProcedureId, get_all_test_procedures
from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi_async_sqlalchemy import db
from fastapi_pagination import Page, paginate
from fastapi_pagination.utils import disable_installed_extensions_check

from cactus_orchestrator.api.run import map_run_to_run_response, select_user_run_group_or_raise
from cactus_orchestrator.auth import AuthPerm, UserContext, jwt_validator
from cactus_orchestrator.crud import select_group_runs_aggregated_by_procedure, select_group_runs_for_procedure
from cactus_orchestrator.schema import (
    CSIPAusVersionResponse,
    RunResponse,
    TestProcedureResponse,
    TestProcedureRunSummaryResponse,
)

logger = logging.getLogger(__name__)


router = APIRouter()

disable_installed_extensions_check()


def map_from_definitions_to_responses(definitions: dict[TestProcedureId, TestProcedure]) -> list[TestProcedureResponse]:
    responses = []
    for k, v in definitions.items():
        if k not in TestProcedureId:
            continue

        responses.append(
            TestProcedureResponse(
                test_procedure_id=TestProcedureId(k), description=v.description, category=v.category, classes=v.classes
            )
        )
    return responses


def map_versions() -> list[CSIPAusVersionResponse]:
    return [CSIPAusVersionResponse(version=v.value) for v in CSIPAusVersion]


# Test procedures
test_procedures_by_id = get_all_test_procedures()
test_procedure_responses = map_from_definitions_to_responses(test_procedures_by_id)
version_responses = map_versions()


@router.get("/version", status_code=HTTPStatus.OK)
async def get_versions_list_paginated(
    _: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
) -> Page[CSIPAusVersionResponse]:
    return paginate(version_responses)


@router.get("/procedure", status_code=HTTPStatus.OK)
async def get_test_procedure_list_paginated(
    _: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
) -> Page[TestProcedureResponse]:
    return paginate(test_procedure_responses)


@router.get("/procedure/{test_procedure_id}", status_code=HTTPStatus.OK)
async def get_test_procedure_yaml(
    test_procedure_id: str,
    _: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
) -> Response:

    if test_procedure_id not in TestProcedureId:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail=f"{test_procedure_id} doesn't map to a test procedure"
        )

    try:
        file_name = (
            resources.files("cactus_test_definitions.client.procedures")
            / f"{TestProcedureId(test_procedure_id).value}.yaml"
        )
        with resources.as_file(file_name) as yaml_file:
            with open(yaml_file, "r") as fp:
                text = fp.read()
    except Exception as exc:
        logger.error(f"Error reading test procedure {test_procedure_id}", exc_info=exc)
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail=f"{test_procedure_id} isn't available on this instance"
        )

    return Response(content=text, status_code=200, media_type="application/yaml")


@router.get("/procedure_runs/{run_group_id}", status_code=HTTPStatus.OK)
async def get_procedure_run_summaries_for_group(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
    run_group_id: int,
) -> list[TestProcedureRunSummaryResponse]:
    """Will not serve summaries for test procedures outside the RunGroup csip_aus_version"""
    # Check permissions
    (_, run_group) = await select_user_run_group_or_raise(db.session, user_context, run_group_id)

    # Enumerate our aggregated summaries from the DB and combine them with additional metadata from the YAML definitions
    results: list[TestProcedureRunSummaryResponse] = []
    for agg in await select_group_runs_aggregated_by_procedure(db.session, run_group_id):
        definition = test_procedures_by_id.get(agg.test_procedure_id, None)
        if definition and (run_group.csip_aus_version in definition.target_versions):
            results.append(
                TestProcedureRunSummaryResponse(
                    test_procedure_id=agg.test_procedure_id,
                    description=definition.description,
                    category=definition.category,
                    classes=definition.classes,
                    run_count=agg.count,
                    latest_all_criteria_met=agg.latest_all_criteria_met,
                    latest_run_status=agg.latest_run_status,
                    latest_run_id=agg.latest_run_id,
                    latest_run_timestamp=agg.latest_run_timestamp,
                )
            )

    return results


@router.get("/procedure_runs/{run_group_id}/{test_procedure_id}", status_code=HTTPStatus.OK)
async def get_runs_for_procedure_in_group(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
    run_group_id: int,
    test_procedure_id: str,
) -> Page[RunResponse]:
    # Check permissions
    await select_user_run_group_or_raise(db.session, user_context, run_group_id)

    # Get runs
    runs = await select_group_runs_for_procedure(db.session, run_group_id, test_procedure_id)

    if runs:
        resp = [map_run_to_run_response(run) for run in runs if run]
    else:
        resp = []
    return paginate(resp)
