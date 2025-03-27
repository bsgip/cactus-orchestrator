from cactus_test_definitions import TestProcedureId
from pydantic import BaseModel


class StartRunRequest(BaseModel):
    test_procedure_id: TestProcedureId


# TODO: what should response be?
class StartRunResponse(BaseModel):
    run_id: int


class RunResponse(BaseModel):
    run_id: int
    test_procedure_id: str
    test_url: str
    finalised: bool


class UserContext(BaseModel):
    """Model for validated user context"""

    subject_id: str
    issuer_id: str


class TestProcedureResponse(BaseModel):
    __test__ = False
    test_procedure_id: TestProcedureId
    description: str
    category: str
