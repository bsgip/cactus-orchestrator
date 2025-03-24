import logging
from http import HTTPStatus
from typing import Annotated

from cactus_test_definitions import TestProcedureConfig, TestProcedures
from fastapi import APIRouter, Depends
from fastapi_pagination import Page, paginate
from fastapi_pagination.utils import disable_installed_extensions_check

from cactus_orchestrator.auth import AuthScopes, jwt_validator
from cactus_orchestrator.schema import TestProcedureResponse, UserContext

logger = logging.getLogger(__name__)


router = APIRouter()

disable_installed_extensions_check()

def map_from_definitions_to_responses(definitions: TestProcedures) -> tuple[list[TestProcedureResponse], list[str]]:
    responses = []
    codes = []
    for k, v in definitions.test_procedures.items():
        if k in codes:
            raise ValueError(f"Duplicate test procedure code: {k}")
        responses.append(TestProcedureResponse(code=k, description=v.description, category=v.category))
        codes.append(k)
    return responses, codes


# Test procedures
test_procedure_responses, available_codes = map_from_definitions_to_responses(TestProcedureConfig.from_resource())


@router.get("/procedure", status_code=HTTPStatus.OK)
async def get_test_procedure_list_paginated(
    _: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
) -> Page[TestProcedureResponse]:
    return paginate(test_procedure_responses)
