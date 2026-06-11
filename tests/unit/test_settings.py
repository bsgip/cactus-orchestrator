import os

from assertical.asserts.type import assert_dict_type

from cactus_orchestrator.pod.models import PodImages
from cactus_orchestrator.settings import CactusOrchestratorSettings


def test_parse_images_from_env_empty(preserved_environment):
    settings = CactusOrchestratorSettings()  # ty:ignore[missing-argument]

    assert_dict_type(str, PodImages, settings.images, count=0)


def test_parse_images_from_env(preserved_environment):

    os.environ["CACTUS_IMAGE__V1_99__CSIP_AUS_VERSION"] = "v1.99"
    os.environ["CACTUS_IMAGE__V1_99__POSTGRES"] = "postgres:111"
    os.environ["CACTUS_IMAGE__V1_99__RABBITMQ"] = "rabbitmq:222"
    os.environ["CACTUS_IMAGE__V1_99__INIT"] = "localhost/init-script:333"
    os.environ["CACTUS_IMAGE__V1_99__ENVOY"] = "envoy:444"
    os.environ["CACTUS_IMAGE__V1_99__RUNNER"] = "runner"

    os.environ["CACTUS_IMAGE__V1_88_STORAGE_BETA__CSIP_AUS_VERSION"] = "v1.88-storage-beta"
    os.environ["CACTUS_IMAGE__V1_88_STORAGE_BETA__POSTGRES"] = "postgres:1"
    os.environ["CACTUS_IMAGE__V1_88_STORAGE_BETA__RABBITMQ"] = "rabbitmq:2"
    os.environ["CACTUS_IMAGE__V1_88_STORAGE_BETA__INIT"] = "localhost/init-script:3"
    os.environ["CACTUS_IMAGE__V1_88_STORAGE_BETA__ENVOY"] = "envoy:4"
    os.environ["CACTUS_IMAGE__V1_88_STORAGE_BETA__RUNNER"] = "runner"

    settings = CactusOrchestratorSettings()  # ty:ignore[missing-argument]

    assert_dict_type(str, PodImages, settings.images, count=2)

    assert settings.images["v1.99"].csip_aus_version == "v1.99"
    assert settings.images["v1.99"].postgres == "postgres:111"
    assert settings.images["v1.99"].rabbitmq == "rabbitmq:222"
    assert settings.images["v1.99"].init == "localhost/init-script:333"
    assert settings.images["v1.99"].envoy == "envoy:444"
    assert settings.images["v1.99"].runner == "runner"

    assert settings.images["v1.88-storage-beta"].csip_aus_version == "v1.88-storage-beta"
    assert settings.images["v1.88-storage-beta"].postgres == "postgres:1"
    assert settings.images["v1.88-storage-beta"].rabbitmq == "rabbitmq:2"
    assert settings.images["v1.88-storage-beta"].init == "localhost/init-script:3"
    assert settings.images["v1.88-storage-beta"].envoy == "envoy:4"
    assert settings.images["v1.88-storage-beta"].runner == "runner"
