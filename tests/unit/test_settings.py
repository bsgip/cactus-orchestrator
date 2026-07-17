import os

import pytest
from assertical.asserts.type import assert_dict_type

from cactus_orchestrator.pod.models import PodImages
from cactus_orchestrator.settings import CactusOrchestratorSettings


@pytest.fixture
def cleared_env(preserved_environment):
    """Clear out any env variables that might affect the settings before the test (eg: inherited from host machine)"""
    for key in list(os.environ.keys()):
        if key.startswith("CACTUS_IMAGE__"):
            del os.environ[key]


def test_parse_images_from_env_empty(cleared_env):

    settings = CactusOrchestratorSettings()  # ty:ignore[missing-argument]

    assert_dict_type(str, PodImages, settings.images, count=0)


def test_parse_images_from_env(cleared_env):

    os.environ["CACTUS_IMAGE__V1_99__CSIP_AUS_VERSION"] = "v1.99"
    os.environ["CACTUS_IMAGE__V1_99__DB"] = "localhost/cactus-db:111"
    os.environ["CACTUS_IMAGE__V1_99__ENVOY"] = "envoy:444"
    os.environ["CACTUS_IMAGE__V1_99__RUNNER"] = "runner"

    os.environ["CACTUS_IMAGE__V1_88_STORAGE_BETA__CSIP_AUS_VERSION"] = "v1.88-storage-beta"
    os.environ["CACTUS_IMAGE__V1_88_STORAGE_BETA__DB"] = "cactus-db:1"
    os.environ["CACTUS_IMAGE__V1_88_STORAGE_BETA__ENVOY"] = "envoy:4"
    os.environ["CACTUS_IMAGE__V1_88_STORAGE_BETA__RUNNER"] = "runner"

    settings = CactusOrchestratorSettings()  # ty:ignore[missing-argument]

    assert_dict_type(str, PodImages, settings.images, count=2)

    assert settings.images["v1.99"].csip_aus_version == "v1.99"
    assert settings.images["v1.99"].db == "localhost/cactus-db:111"
    assert settings.images["v1.99"].envoy == "envoy:444"
    assert settings.images["v1.99"].runner == "runner"

    assert settings.images["v1.88-storage-beta"].csip_aus_version == "v1.88-storage-beta"
    assert settings.images["v1.88-storage-beta"].db == "cactus-db:1"
    assert settings.images["v1.88-storage-beta"].envoy == "envoy:4"
    assert settings.images["v1.88-storage-beta"].runner == "runner"


def test_dev_runner_localhost_port_base_defaults_off(cleared_env):
    """Makes sure we dont accidentally deploy dev version somehow"""
    assert "DEV_RUNNER_LOCALHOST_PORT_BASE" not in os.environ

    settings = CactusOrchestratorSettings()  # ty:ignore[missing-argument]

    assert settings.dev_runner_localhost_port_base is None
