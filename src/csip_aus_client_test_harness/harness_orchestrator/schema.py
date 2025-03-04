from enum import StrEnum

from pydantic import BaseModel, Secret


class CsipAusTestProcedureCodes(StrEnum):
    ALL01 = "ALL-01"


class StartTestRequest(BaseModel):
    code: CsipAusTestProcedureCodes


# TODO: what should response be?
class StartTestResponse(BaseModel):
    # artefact_download_url: str
    # token: Secret
    ca_cert: bytes  # PEM encoded
    client_p12: bytes  # PKCS#12 (PFX) format
    p12_password: Secret
