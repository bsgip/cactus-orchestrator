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
            # CACTUS_IMAGES__V1_2__POSTGRES → ("V1_2", "postgres")
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

    # test execution URLs
    test_execution_fqdn: str
    test_execution_comms_timeout_seconds: int = 120

    # podman
    podman_socket: str = "/run/podman/podman.sock"
    podman_network: str = (
        "cactus-net"  # The network that the test pods will execute under (and that orchestrator runs in)
    )
    podman_runner_port: int = 8080

    # podman images
    images: dict[str, PodImages]  # PodImages keyed by CSIP-Aus version

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

    # image pull task
    pulltask_repeat_every_seconds: int = 120

    # general options
    ignored_csip_aus_versions: list[str] = []
    ignored_test_procedures: list[str] = []

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
        _main_settings = CactusOrchestratorSettings()  # ty: ignore[missing-argument]
    return _main_settings


def _reset_current_settings() -> None:
    global _main_settings
    _main_settings = None
