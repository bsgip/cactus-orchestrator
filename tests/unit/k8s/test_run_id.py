import re
import unittest.mock as mock
from urllib.parse import urlparse

from assertical.fake.generator import generate_class_instance

from cactus_orchestrator.k8s.run_id import (
    generate_dynamic_test_stack_id,
    generate_envoy_dcap_uri,
    generate_static_test_stack_id,
)
from cactus_orchestrator.model import User
from cactus_orchestrator.settings import CactusOrchestratorSettings


def assert_uri_friendly(s: str):
    assert isinstance(s, str)
    assert re.match("[^a-zA-Z0-9\\-_]", s) is None, "Only URI friendly chars should be encoded"


def test_generate_static_test_stack_id():
    u1 = generate_class_instance(
        User,
        user_id=1,
        is_static_uri=True,
        aggregator_certificate_p12_bundle=[],
        aggregator_certificate_x509_der=[],
        device_certificate_p12_bundle=[],
        device_certificate_x509_der=[],
    )
    u2 = generate_class_instance(
        User,
        user_id=2,
        is_static_uri=True,
        aggregator_certificate_p12_bundle=[],
        aggregator_certificate_x509_der=[],
        device_certificate_p12_bundle=[],
        device_certificate_x509_der=[],
    )

    u1_id = generate_static_test_stack_id(u1)
    assert_uri_friendly(u1_id)

    u2_id = generate_static_test_stack_id(u2)
    assert_uri_friendly(u2_id)

    assert u1_id != u2_id, "Should differ from one user to another"
    assert u1_id == generate_static_test_stack_id(u1), "Should be static"


def test_generate_dynamic_test_stack_id():
    id1 = generate_dynamic_test_stack_id()
    id2 = generate_dynamic_test_stack_id()
    id3 = generate_dynamic_test_stack_id()

    assert_uri_friendly(id1)
    assert_uri_friendly(id2)
    assert_uri_friendly(id3)

    assert len(set([id1, id2, id3])) == 3, "All values must be unique"


@mock.patch("cactus_orchestrator.k8s.run_id.get_current_settings")
def test_generate_envoy_dcap_uri(mock_get_current_settings: mock.MagicMock):

    # Arrange
    service_name = "my-svc-name"
    fqdn = "my.host.name"
    test_stack_id = "abc123-my-id"
    mock_get_current_settings.return_value = generate_class_instance(
        CactusOrchestratorSettings,
        template_service_name=service_name,
        test_execution_fqdn=fqdn,
        orchestrator_database_url="",
    )

    # Act
    uri = generate_envoy_dcap_uri(test_stack_id)

    # Assert
    result = urlparse(uri)
    assert result.hostname == f"{fqdn}"
    assert result.path.endswith("/dcap")
    assert "//" not in result.path
    assert service_name in result.path
    assert test_stack_id in result.path
    assert not result.query
