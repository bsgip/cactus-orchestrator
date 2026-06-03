import logging

from pydantic import PostgresDsn
from pydantic_settings import BaseSettings

from cactus_orchestrator.teststack.images import TeststackImages

TEST_EXECUTION_URL_FORMAT = "https://{fqdn}/{svc_name}"
PODMAN_RUNNER_URL = "http://{pod_name}:{svc_port}"

logger = logging.getLogger(__name__)


class CactusOrchestratorError(Exception): ...  # noqa: E701


class CactusOrchestratorSettings(BaseSettings):
    # database
    orchestrator_database_url: PostgresDsn

    # test execution URLs
    test_execution_fqdn: str
    test_execution_comms_timeout_seconds: int = 120

    # teststack pod naming — prefix applied to teststack_id to form pod name and external URL path
    template_service_name_prefix: str = "envoy-svc-"

    # podman
    podman_socket: str = "/run/podman/podman.sock"
    podman_network: str = "cactus-net"
    podman_runner_port: int = 8080
    # JSON map: csip_aus_version → image references for that version's teststack containers
    podman_teststack_images: dict[str, TeststackImages] = {}

    # certificates (file paths)
    cert_serca_path: str = ""  # path to SERCA ca.crt PEM file
    cert_mca_path: str = ""  # path to MCA ca.crt PEM file
    cert_mica_crt_path: str = ""  # path to MICA tls.crt PEM file
    cert_mica_key_path: str = ""  # path to MICA tls.key PEM file

    # teardown task
    idleteardowntask_enable: bool = True
    idleteardowntask_max_lifetime_seconds: int = 3600 * 24 * 4
    idleteardowntask_idle_timeout_seconds: int = 7200
    idleteardowntask_repeat_every_seconds: int = 120

    # general options
    ignored_csip_aus_versions: list[str] = []
    ignored_test_procedures: list[str] = []


class JWTAuthSettings(BaseSettings):
    jwks_url: str
    issuer: str
    audience: str

    class Config:
        env_prefix = "JWTAUTH_"


_main_settings: CactusOrchestratorSettings | None = None


def get_current_settings() -> CactusOrchestratorSettings:
    global _main_settings
    if not _main_settings:
        _main_settings = CactusOrchestratorSettings()  # ty: ignore[missing-argument]
    return _main_settings


def _reset_current_settings() -> None:
    global _main_settings
    _main_settings = None
