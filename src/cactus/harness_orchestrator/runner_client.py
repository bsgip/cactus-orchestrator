# TODO: this is currently just a stub / example
import logging
import base64
from enum import StrEnum

import hashlib
import urllib
import httpx
from pydantic import BaseModel


logger = logging.getLogger(__name__)


class RunnerClientException(Exception): ...


class CsipAusTestProcedureCodes(StrEnum):
    ALL01 = "ALL-01"


# TODO: ideally we send cert not lfdi
class StartTestRequest(BaseModel):
    client_cert: str


# TODO: harness runner may need to expose two separate services, one for
# this orchestrator and other for proxying testing client requests.
class HarnessRunnerAsyncClient:
    def __init__(self, pod_fqdn: str, runner_port: int):
        self.url = httpx.URL("//" + pod_fqdn.lstrip("/"), scheme="http", port=runner_port)

    async def post_start_test(self, test_code: CsipAusTestProcedureCodes, body: StartTestRequest) -> None:
        try:
            # TODO: logging, retries, exception handling
            async with httpx.AsyncClient() as client:
                _ = await client.post(
                    self.url.join("/start"),
                    json=body.model_dump_json(),
                    params=httpx.QueryParams(
                        {"test": test_code.value, "lfdi": generate_lfdi_from_pem(body.client_cert)}
                    ),
                    timeout=30,
                )
        except httpx.TimeoutException as exc:
            logger.debug(exc)
            raise RunnerClientException("Unexpected failed while starting test.")

    async def post_finalize_test(self) -> None:
        # TODO:  None
        ...


def generate_lfdi_from_pem(cert_pem: str) -> str:
    """This function generates the sep2 / 2030.5-2018 lFDI (Long-form device identifier) from the device's
    TLS certificate in pem (Privacy Enhanced Mail) format, i.e. Base64 encoded DER
    (Distinguished Encoding Rules) certificate, as described in Section 6.3.4
    of IEEE Std 2030.5-2018.

    The lFDI is derived, from the certificate in PEM format, according to the following steps:
        1- Base64 decode the PEM to DER.
        2- Performing SHA256 hash on the DER to generate the certificate fingerprint.
        3- Left truncating the certificate fingerprint to 160 bits.

    Args:
        cert_pem: TLS certificate in PEM format.

    Return:
        The lFDI as a hex string.
    """
    # generate lfdi
    return generate_lfdi_from_fingerprint(_cert_pem_to_cert_fingerprint(cert_pem))


def generate_lfdi_from_fingerprint(cert_fingerprint: str) -> str:
    """This function generates the sep2 / 2030.5-2018 lFDI (Long-form device identifier) from the device's
    TLS certificate fingerprint (40 hex chars), as described in Section 6.3.4
    of IEEE Std 2030.5-2018 which states The LFDI SHALL be the certificate fingerprint left-truncated to
    160 bits (20 octets).

    Args:
        cert_pem: TLS certificate in PEM format.

    Return:
        The lFDI as a hex string.
    """
    # generate lfdi
    return cert_fingerprint[:40]


def _cert_pem_to_cert_fingerprint(cert_pem_b64: str) -> str:
    """The certificate fingerprint is the result of performing a SHA256 operation over the whole DER-encoded
    certificate and is used to derive the SFDI and LFDI"""
    # Replace %xx escapes with their single-character equivalent
    cert_pem_b64 = urllib.parse.unquote(cert_pem_b64)

    # remove header/footer
    cert_pem_b64 = "\n".join(cert_pem_b64.splitlines()[1:-1])

    # decode base64
    cert_pem_bytes = base64.b64decode(cert_pem_b64)

    # sha256 hash
    hashing_obj = hashlib.sha256(cert_pem_bytes)
    return hashing_obj.hexdigest()
