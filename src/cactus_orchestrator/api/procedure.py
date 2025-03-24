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


def map_from_definitions_to_responses(definitions: TestProcedures) -> list[TestProcedureResponse]:
    responses = []
    test_procedure_ids = []
    for k, v in definitions.test_procedures.items():
        if k in test_procedure_ids:
            continue
        responses.append(TestProcedureResponse(test_procedure_id=k, description=v.description, category=v.category))
        test_procedure_ids.append(k)
    return responses


# Test procedures
test_procedure_responses = map_from_definitions_to_responses(TestProcedureConfig.from_resource())


@router.get("/procedure", status_code=HTTPStatus.OK)
async def get_test_procedure_list_paginated(
    _: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_scopes({AuthScopes.user_all}))],
) -> Page[TestProcedureResponse]:
    return paginate(test_procedure_responses)
