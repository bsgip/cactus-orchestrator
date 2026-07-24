import logging
import os
from collections import defaultdict

from pydantic import PostgresDsn
from pydantic.fields import FieldInfo
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource

from cactus_orchestrator.pod.models import PodImages

logger = logging.getLogger(__name__)


class CactusOrchestratorError(Exception): ...  # noqa: E701


class ImagesEnvSource(PydanticBaseSettingsSource):
    """
    Parses CACTUS_IMAGE__<version_key>__<field> env vars into dict[str, PodImages].
    Only handles the `images` field — everything else is left to other sources.
    """

    PREFIX = "CACTUS_IMAGE__"

    def get_field_value(self, field: FieldInfo, field_name: str) -> tuple[dict | None, str, bool]:
        if field_name != "images":
            return None, field_name, False

        nested = defaultdict(dict)
        for key, val in os.environ.items():
            if not key.upper().startswith(self.PREFIX):
                continue
            # CACTUS_IMAGES__V1_2__DB → ("V1_2", "db")
            remainder = key[len(self.PREFIX) :]
            parts = remainder.split("__", 1)
            if len(parts) != 2:
                continue
            version_key, field_key = parts
            nested[version_key][field_key.lower()] = val

        images = {v["csip_aus_version"]: PodImages(**v) for v in nested.values()}
        return images, field_name, False

    def __call__(self) -> dict:
        return {
            field_name: self.get_field_value(field_info, field_name)[0]
            for field_name, field_info in self.settings_cls.model_fields.items()
            if self.get_field_value(field_info, field_name)[0] is not None
        }


class CactusOrchestratorSettings(BaseSettings):
    # database
    orchestrator_database_url: PostgresDsn

    # domain
    cactus_fqdn: str  # The Fully Qualified Domain Name under which this service is hosted. eg 'cactus.example.com'
    comms_timeout_seconds: int = 120
    envoy_prefix: str = "/envoy"  # The href prefix that envoy (in test pods) will be deployed under

    # podman
    podman_socket: str = "/run/podman/podman.sock"
    podman_network: str = (
        "cactus-net"  # The network that the test pods will execute under (and that orchestrator runs in)
    )
    podman_runner_port: int = 8080

    # podman images
    images: dict[str, PodImages]  # PodImages keyed by CSIP-Aus version

    # certificates (file paths)
    # Shared trust anchor for every chain below.
    cert_serca_path: str = ""  # path to SERCA ca.crt PEM file

    # Device signing chain: SERCA -> Device MCA -> Device MICA -> Device EE (issued per run group).
    cert_device_mca_path: str = ""  # path to Device MCA ca.crt PEM file
    cert_device_mica_crt_path: str = ""  # path to Device MICA tls.crt PEM file
    cert_device_mica_key_path: str = ""  # path to Device MICA tls.key PEM file (signs device EE certs)

    # Aggregator signing chain: SERCA -> Agg PCA -> Agg ICA -> Aggregator EE (issued per run group, carries domain SAN).
    cert_agg_pca_path: str = ""  # path to Aggregator PCA ca.crt PEM file
    cert_agg_ica_crt_path: str = ""  # path to Aggregator ICA tls.crt PEM file
    cert_agg_ica_key_path: str = ""  # path to Aggregator ICA tls.key PEM file (signs aggregator EE certs)

    # Utility-server (envoy / DNSP) chain: SERCA -> envoy PCA -> envoy ICA -> envoy EE.
    cert_envoy_ee_fullchain_path: str = ""  # path to envoy (DNSP) EE + ICA + PCA fullchain PEM file
    cert_envoy_ee_key_path: str = ""  # path to envoy (DNSP) EE tls.key PEM file

    # teardown task
    idleteardowntask_enable: bool = True
    idleteardowntask_max_lifetime_seconds: int = 3600 * 24 * 4
    idleteardowntask_idle_timeout_seconds: int = 7200
    idleteardowntask_repeat_every_seconds: int = 120
    idleteardowntask_startup_grace_seconds: int = 300  # Runs have this much time to start before being orphaned

    # image pull task
    pulltask_repeat_every_seconds: int = 120

    # general options
    ignored_csip_aus_versions: list[str] = []
    ignored_test_procedures: list[str] = []

    # LOCAL DEV ONLY - never set in production. When set, each pod's runner port is also published to
    # 127.0.0.1:<port> on the host and the orchestrator addresses runners via localhost instead
    # of pod-name DNS - allowing the orchestrator to run outside podman_network.
    dev_runner_localhost_port_base: int | None = None

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            ImagesEnvSource(settings_cls),  # handles `images`
            env_settings,  # handles everything else
            dotenv_settings,
            file_secret_settings,
        )


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
        _main_settings = CactusOrchestratorSettings()
    return _main_settings


def _reset_current_settings() -> None:
    global _main_settings
    _main_settings = None
