"""TODO: Migrate to modern asyncio-compatible + typed kubernetes library"""

import re
from unittest.mock import patch

import pytest
from assertical.fake.generator import generate_class_instance
from cactus_test_definitions import CSIPAusVersion
from kubernetes import client

from cactus_orchestrator.k8s.resource import (
    RunResourceNames,
    TemplateResourceNames,
    csip_aus_version_to_k8s_id,
    generate_dynamic_test_stack_id,
    generate_envoy_dcap_uri,
    generate_static_test_stack_id,
)
from cactus_orchestrator.k8s.resource.create import add_ingress_rule, clone_service, clone_statefulset, wait_for_pod
from cactus_orchestrator.k8s.resource.delete import delete_service, delete_statefulset, remove_ingress_rule
from cactus_orchestrator.model import User
from cactus_orchestrator.settings import DEFAULT_INGRESS_PATH_FORMAT, CactusOrchestratorException


@pytest.mark.asyncio
@patch("cactus_orchestrator.k8s.resource.create.v1_core_api")
async def test_clone_service(mock_v1_core_api, mock_thread_cls):
    # Arrange
    mock_service = client.V1Service(
        api_version="v1",
        kind="Service",
        metadata=client.V1ObjectMeta(name="template-service"),
        spec=client.V1ServiceSpec(ports=[client.V1ServicePort(port=80)]),
    )
    template_resource_names = generate_class_instance(TemplateResourceNames, seed=101)
    run_resource_names = generate_class_instance(RunResourceNames, seed=202)

    mock_v1_core_api.read_namespaced_service.return_value = mock_thread_cls(mock_service)
    mock_v1_core_api.create_namespaced_service.return_value = mock_thread_cls(None)

    # Act
    await clone_service(template_resource_names, run_resource_names)

    # Assert
    mock_v1_core_api.read_namespaced_service.assert_called_once()
    mock_v1_core_api.create_namespaced_service.assert_called_once()


@pytest.mark.asyncio
@patch("cactus_orchestrator.k8s.resource.create.v1_app_api")
async def test_clone_statefulset(mock_v1_app_api, mock_thread_cls):
    """Test cloning a Kubernetes StatefulSet."""
    container_foo = client.V1Container(name="foo")
    container_envoy = client.V1Container(name="envoy")
    container_taskiq_worker = client.V1Container(name="taskiq_worker", env=[client.V1EnvVar(name="MYENV", value="123")])
    container_bar = client.V1Container(name="bar", env=[client.V1EnvVar(name="MYENV2", value="456")])
    mock_statefulset = client.V1StatefulSet(
        api_version="apps/v1",
        kind="StatefulSet",
        metadata=client.V1ObjectMeta(name="template-statefulset"),
        spec=client.V1StatefulSetSpec(
            service_name="template-service",
            selector=client.V1LabelSelector(match_labels={"app": "template-app"}),
            template=client.V1PodTemplateSpec(
                metadata=client.V1ObjectMeta(labels={"app": "template-app"}),
                spec=client.V1PodSpec(
                    containers=[container_foo, container_envoy, container_taskiq_worker, container_bar]
                ),
            ),
        ),
    )
    template_resource_names = generate_class_instance(TemplateResourceNames, seed=101)
    run_resource_names = generate_class_instance(RunResourceNames, seed=202)

    mock_v1_app_api.read_namespaced_stateful_set.return_value = mock_thread_cls(mock_statefulset)
    mock_v1_app_api.create_namespaced_stateful_set.return_value = mock_thread_cls(None)

    await clone_statefulset(template_resource_names, run_resource_names)

    mock_v1_app_api.read_namespaced_stateful_set.assert_called_once()
    mock_v1_app_api.create_namespaced_stateful_set.assert_called_once()

    # Ensure the HREF_PREFIX env var got injected (to the correct container)
    assert container_foo.env is None
    assert container_envoy.env is not None
    assert container_taskiq_worker.env is not None
    assert container_bar.env == [client.V1EnvVar(name="MYENV2", value="456")], "Should be unchanged"

    # The envoy container had NO env vars
    assert len(container_envoy.env) == 1
    assert container_envoy.env[0].name == "HREF_PREFIX"
    assert container_envoy.env[0].value == "/" + run_resource_names.service

    # We added the env to the taskiq_worker list
    assert len(container_taskiq_worker.env) == 2
    assert container_taskiq_worker.env[0].name == "MYENV"
    assert container_taskiq_worker.env[0].value == "123"
    assert container_taskiq_worker.env[1].name == "HREF_PREFIX"
    assert container_taskiq_worker.env[1].value == "/" + run_resource_names.service


@pytest.mark.asyncio
@patch("cactus_orchestrator.k8s.resource.create.is_pod_ready", return_value=True)
async def test_wait_for_pod(mock_is_pod_ready):
    """Test waiting for a pod to be ready."""
    run_resource_names = generate_class_instance(RunResourceNames, seed=202)
    await wait_for_pod(run_resource_names)
    mock_is_pod_ready.assert_called_once()


@pytest.mark.asyncio
@patch("cactus_orchestrator.k8s.resource.create.is_pod_ready", return_value=False)
async def test_wait_for_pod_retries(mock_is_pod_ready):
    """Test waiting for a pod to be ready."""
    run_resource_names = generate_class_instance(RunResourceNames, seed=202)

    with pytest.raises(CactusOrchestratorException):
        await wait_for_pod(run_resource_names, 2, wait_interval=1)

    assert mock_is_pod_ready.call_count == 2


@pytest.mark.asyncio
@patch("cactus_orchestrator.k8s.resource.create.is_pod_ready", side_effect=Exception("mock exception"))
async def test_wait_for_pod_retries_exception(mock_is_pod_ready):
    """Test waiting for a pod to be ready - even if exceptions happen."""
    run_resource_names = generate_class_instance(RunResourceNames, seed=202)

    with pytest.raises(CactusOrchestratorException):
        await wait_for_pod(run_resource_names, 2, wait_interval=1)

    assert mock_is_pod_ready.call_count == 2


@pytest.mark.asyncio
@patch("cactus_orchestrator.k8s.resource.create.v1_net_api")
async def test_add_ingress_rule(mock_v1_net_api, mock_thread_cls):
    """Test adding an ingress rule to Kubernetes."""
    # Arrange
    mock_ingress = client.V1Ingress(
        spec=client.V1IngressSpec(rules=[client.V1IngressRule(http=client.V1HTTPIngressRuleValue(paths=[]))])
    )
    run_resource_names = generate_class_instance(RunResourceNames, seed=202)

    mock_v1_net_api.read_namespaced_ingress.return_value = mock_thread_cls(mock_ingress)
    mock_v1_net_api.patch_namespaced_ingress.return_value = mock_thread_cls(None)

    # Act
    await add_ingress_rule(run_resource_names)

    # Assert
    mock_v1_net_api.read_namespaced_ingress.assert_called_once()
    mock_v1_net_api.patch_namespaced_ingress.assert_called_once()


@pytest.mark.asyncio
@patch("cactus_orchestrator.k8s.resource.delete.v1_core_api")
async def test_delete_service(mock_v1_core_api, mock_thread_cls):
    """Test deleting a Kubernetes Service."""
    # Arrange
    mock_v1_core_api.delete_namespaced_service.return_value = mock_thread_cls(None)
    run_resource_names = generate_class_instance(RunResourceNames, seed=202)

    # Act
    await delete_service(run_resource_names)

    # Assert
    mock_v1_core_api.delete_namespaced_service.assert_called_once()


@pytest.mark.asyncio
@patch("cactus_orchestrator.k8s.resource.delete.v1_app_api")
async def test_delete_statefulset(mock_v1_app_api, mock_thread_cls):
    """Test deleting a Kubernetes StatefulSet."""
    # Arrange
    mock_v1_app_api.delete_namespaced_stateful_set.return_value = mock_thread_cls(None)
    run_resource_names = generate_class_instance(RunResourceNames, seed=202)

    # Act
    await delete_statefulset(run_resource_names)

    # Assert
    mock_v1_app_api.delete_namespaced_stateful_set.assert_called_once()


@pytest.mark.asyncio
@patch("cactus_orchestrator.k8s.resource.delete.v1_net_api")
async def test_remove_ingress_rule(mock_v1_net_api, generate_k8s_class_instance, mock_thread_cls):
    """Test removing an ingress rule from Kubernetes."""

    # Arrange
    mock_ingress = generate_k8s_class_instance(client.V1Ingress)
    mock_ingress.spec.rules = [
        generate_k8s_class_instance(
            client.V1IngressRule,
            http=generate_k8s_class_instance(
                client.V1HTTPIngressRuleValue,
                paths=[
                    generate_k8s_class_instance(
                        client.V1HTTPIngressPath,
                        path=DEFAULT_INGRESS_PATH_FORMAT.format(svc_name="remove-me"),
                        path_type="Prefix",
                    )
                ],
            ),
        )
    ]
    run_resource_names = generate_class_instance(RunResourceNames, seed=202, service="remove-me")

    mock_v1_net_api.read_namespaced_ingress.return_value = mock_thread_cls(mock_ingress)
    mock_v1_net_api.patch_namespaced_ingress.return_value = mock_thread_cls(None)

    # Act
    await remove_ingress_rule(run_resource_names)

    # Assert
    mock_v1_net_api.read_namespaced_ingress.assert_called_once()
    mock_v1_net_api.patch_namespaced_ingress.assert_called_once()
    assert len(mock_ingress.spec.rules[0].http.paths) == 0


def assert_uri_friendly(s: str):
    assert isinstance(s, str)
    assert re.match("[^a-zA-Z0-9\\-_]", s) is None, "Only URI friendly chars should be encoded"


def test_generate_static_test_stack_id():
    u1 = generate_class_instance(User, user_id=1, is_static_uri=True)
    u2 = generate_class_instance(User, user_id=2, is_static_uri=True)

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


def test_generate_envoy_dcap_uri():

    # Arrange
    run_resource_names = generate_class_instance(RunResourceNames)

    # Act
    uri = generate_envoy_dcap_uri(run_resource_names)

    # Assert
    assert uri.startswith(run_resource_names.envoy_base_url)


@pytest.mark.parametrize(
    "input, expected",
    [
        ("a", "a"),
        ("abc123DEF", "abc123def"),
        ("ab/c-123-DE/F", "ab-c-123-de-f"),
        ("lot's of .!@#$%^&*()[]}{- chars)", "lot-s-of------------------chars-"),
        (CSIPAusVersion.RELEASE_1_2.value, "v1-2"),
        (CSIPAusVersion.BETA_1_3_STORAGE.value, "v1-3-beta-storage"),
    ],
)
def test_csip_aus_version_to_k8s_id(input: str, expected: str):
    result = csip_aus_version_to_k8s_id(input)
    assert isinstance(result, str)
    assert result == expected
