from pydantic import BaseModel, Field, SecretStr, field_serializer

from cactus_orchestrator.runner_client import CsipAusTestProcedureCodes


class SpawnTestRequest(BaseModel):
    code: CsipAusTestProcedureCodes


# TODO: what should response be?
class SpawnTestResponse(BaseModel):
    test_url: str
    run_id: str


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
    id_: str = Field(alias="id")
    description: str
    category: str
