from pydantic import BaseModel, Secret, field_serializer

from cactus.harness_orchestrator.runner_client import CsipAusTestProcedureCodes


class SpawnTestRequest(BaseModel):
    code: CsipAusTestProcedureCodes


# TODO: what should response be?
class SpawnTestResponse(BaseModel):
    # artefact_download_url: str
    # token: Secret
    ca_cert: str  # PEM encoded
    client_p12: str  # PKCS#12 (PFX) format
    p12_password: Secret[str]
    test_url: str

    @field_serializer("p12_password", when_used="json")
    def dump_secret(self, v):
        return v.get_secret_value()
