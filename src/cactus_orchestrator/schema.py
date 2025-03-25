from pydantic import BaseModel, SecretStr, field_serializer

from cactus_test_definitions import TestProcedureId


class StartRunRequest(BaseModel):
    test_procedure_id: TestProcedureId


# TODO: what should response be?
class StartRunResponse(BaseModel):
    run_id: int
    test_url: str


class RunResponse(BaseModel):
    run_id: int
    test_procedure_id: str
    test_url: str
    finalised: bool


class UserContext(BaseModel):
    """Model for validated user context"""

    subject_id: str
    issuer_id: str


class UserResponse(BaseModel):
    user_id: int
    certificate_p12_b64: str
    password: SecretStr | None

    @field_serializer("password", when_used="json")
    def dump_secret(self, v: SecretStr) -> str:
        return v.get_secret_value()


class TestProcedureResponse(BaseModel):
    __test__ = False
    test_procedure_id: TestProcedureId
    description: str
    category: str
