import logging
from http import HTTPStatus
from importlib import resources
from typing import Annotated

from cactus_test_definitions import TestProcedureConfig, TestProcedureId, TestProcedures
from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi_pagination import Page, paginate
from fastapi_pagination.utils import disable_installed_extensions_check

from cactus_orchestrator.auth import AuthScopes, jwt_validator
from cactus_orchestrator.schema import TestProcedureResponse, UserContext

logger = logging.getLogger(__name__)


router = APIRouter()

disable_installed_extensions_check()


def map_from_definitions_to_responses(definitions: TestProcedures) -> list[TestProcedureResponse]:
    responses = []
    test_procedure_ids = []
    for k, v in definitions.test_procedures.items():
        if k in test_procedure_ids or k not in TestProcedureId:
            continue
        responses.append(
            TestProcedureResponse(test_procedure_id=TestProcedureId(k), description=v.description, category=v.category)
        )
        test_procedure_ids.append(k)
    return responses


# Test procedures
test_procedure_responses = map_from_definitions_to_responses(TestProcedureConfig.from_resource())


@router.get("/procedure", status_code=HTTPStatus.OK)
async def get_test_procedure_list_paginated(
    _: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
) -> Page[TestProcedureResponse]:
    return paginate(test_procedure_responses)


@router.get("/procedure/{test_procedure_id}", status_code=HTTPStatus.OK)
async def get_test_procedure_yaml(
    test_procedure_id: str,
    _: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
) -> Response:

    if test_procedure_id not in TestProcedureId:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail=f"{test_procedure_id} doesn't map to a test procedure"
        )

    try:
        file_name = (
            resources.files("cactus_test_definitions.procedures") / f"{TestProcedureId(test_procedure_id).value}.yaml"
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
