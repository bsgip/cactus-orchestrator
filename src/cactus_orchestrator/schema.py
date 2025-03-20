from pydantic import BaseModel, SecretStr, field_serializer

from cactus_orchestrator.runner_client import CsipAusTestProcedureCodes


class SpawnTestRequest(BaseModel):
    code: CsipAusTestProcedureCodes


# TODO: what should response be?
class SpawnTestResponse(BaseModel):
    # artefact_download_url: str
    # token: Secret
    # ca_cert: str  # PEM encoded
    # client_p12: str  # PKCS#12 (PFX) format
    # p12_password: SecretStr
    test_url: str
    run_id: str

    # @field_serializer("p12_password", when_used="json")
    # def dump_secret(self, v: SecretStr) -> str:
    #     return v.get_secret_value()


# TODO:
class FinalizeTestResponse(BaseModel): ...


class UserContext(BaseModel):
    """Model for validated user context"""

    subject_id: str
    issuer_id: str


class UserResponse(BaseModel):
    certificate_p12_b64: str
    password: SecretStr | None

    @field_serializer("password", when_used="json")
    def dump_secret(self, v: SecretStr) -> str:
        return v.get_secret_value()
