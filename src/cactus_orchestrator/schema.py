from pydantic import BaseModel, SecretStr, field_serializer

from cactus_orchestrator.runner_client import CsipAusTestProcedureCodes


class SpawnTestProcedureRequest(BaseModel):
    test_procedure_id: CsipAusTestProcedureCodes


# TODO: what should response be?
class SpawnTestProcedureResponse(BaseModel):
    run_id: int
    test_url: str


class RunResponse(BaseModel):
    run_id: int
    test_procedure_id: str
    test_url: str
    finalised: bool


# TODO:
class FinalizeTestResponse(BaseModel): ...  # noqa: E701


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
    test_procedure_id: CsipAusTestProcedureCodes
    description: str
    category: str
