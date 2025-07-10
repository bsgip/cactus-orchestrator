"""TODO: Migrate to modern asyncio-compatible + typed kubernetes library"""

from unittest.mock import patch

import pytest
from kubernetes import client

from cactus_orchestrator.k8s.resource.create import (
    add_ingress_rule,
    clone_service,
    clone_statefulset,
    is_container_ready,
    wait_for_pod,
)
from cactus_orchestrator.k8s.resource.delete import delete_service, delete_statefulset, remove_ingress_rule
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

    mock_v1_core_api.read_namespaced_service.return_value = mock_thread_cls(mock_service)
    mock_v1_core_api.create_namespaced_service.return_value = mock_thread_cls(None)

    # Act
    await clone_service("new-service", "new-app-label")

    # Assert
    mock_v1_core_api.read_namespaced_service.assert_called_once()
    mock_v1_core_api.create_namespaced_service.assert_called_once()


@pytest.mark.asyncio
@patch("cactus_orchestrator.k8s.resource.create.v1_app_api")
async def test_clone_statefulset(mock_v1_app_api, mock_thread_cls):
    """Test cloning a Kubernetes StatefulSet."""
    container_foo = client.V1Container(name="foo")
    container_envoy = client.V1Container(name="envoy")
    mock_statefulset = client.V1StatefulSet(
        api_version="apps/v1",
        kind="StatefulSet",
        metadata=client.V1ObjectMeta(name="template-statefulset"),
        spec=client.V1StatefulSetSpec(
            service_name="template-service",
            selector=client.V1LabelSelector(match_labels={"app": "template-app"}),
            template=client.V1PodTemplateSpec(
                metadata=client.V1ObjectMeta(labels={"app": "template-app"}),
                spec=client.V1PodSpec(containers=[container_foo, container_envoy]),
            ),
        ),
    )

    mock_v1_app_api.read_namespaced_stateful_set.return_value = mock_thread_cls(mock_statefulset)
    mock_v1_app_api.create_namespaced_stateful_set.return_value = mock_thread_cls(None)

    await clone_statefulset("new-statefulset", "new-service", "new-app-label")

    mock_v1_app_api.read_namespaced_stateful_set.assert_called_once()
    mock_v1_app_api.create_namespaced_stateful_set.assert_called_once()

    # Ensure the HREF_PREFIX env var got injected (to the correct container)
    assert container_foo.env is None
    assert container_envoy.env is not None
    assert len(container_envoy.env) == 1
    assert container_envoy.env[0].name == "HREF_PREFIX"
    assert container_envoy.env[0].value == "/new-service"


@pytest.mark.asyncio
@patch("cactus_orchestrator.k8s.resource.create.v1_core_api")
async def test_is_container_ready(mock_v1_core_api, generate_k8s_class_instance, mock_thread_cls):
    """Test checking if a container is ready."""
    # Arrange
    mock_pod = client.V1Pod(
        status=client.V1PodStatus(
            container_statuses=[
                generate_k8s_class_instance(client.V1ContainerStatus, name="blah", ready=True),
                generate_k8s_class_instance(client.V1ContainerStatus, name="envoy", ready=True),
            ]
        )
    )
    mock_v1_core_api.read_namespaced_pod.return_value = mock_thread_cls(mock_pod)

    # Act
    res = await is_container_ready("test-pod")

    # Assert
    mock_v1_core_api.read_namespaced_pod.assert_called_once()
    assert res == True


@pytest.mark.asyncio
@patch("cactus_orchestrator.k8s.resource.create.v1_core_api")
async def test_is_container_ready_not_found(mock_v1_core_api, mock_thread_cls):
    """Test checking container readiness when the container is missing."""
    # Arrange
    mock_pod = client.V1Pod(status=client.V1PodStatus(container_statuses=[]))

    mock_v1_core_api.read_namespaced_pod.return_value = mock_thread_cls(mock_pod)

    # Act
    res = await is_container_ready("test-pod")

    # Assert
    assert res == False


@pytest.mark.asyncio
@patch("cactus_orchestrator.k8s.resource.create.is_pod_ready", return_value=True)
async def test_wait_for_pod(mock_is_pod_ready):
    """Test waiting for a pod to be ready."""
    await wait_for_pod("test-pod")
    mock_is_pod_ready.assert_called_once()


@pytest.mark.asyncio
@patch("cactus_orchestrator.k8s.resource.create.is_pod_ready", return_value=False)
async def test_wait_for_pod_retries(mock_is_pod_ready):
    """Test waiting for a pod to be ready."""

    with pytest.raises(CactusOrchestratorException):
        await wait_for_pod("test-pod", 2, wait_interval=1)

    assert mock_is_pod_ready.call_count == 2


@pytest.mark.asyncio
@patch("cactus_orchestrator.k8s.resource.create.v1_net_api")
async def test_add_ingress_rule(mock_v1_net_api, mock_thread_cls):
    """Test adding an ingress rule to Kubernetes."""
    # Arrange
    mock_ingress = client.V1Ingress(
        spec=client.V1IngressSpec(rules=[client.V1IngressRule(http=client.V1HTTPIngressRuleValue(paths=[]))])
    )

    mock_v1_net_api.read_namespaced_ingress.return_value = mock_thread_cls(mock_ingress)
    mock_v1_net_api.patch_namespaced_ingress.return_value = mock_thread_cls(None)

    # Act
    await add_ingress_rule("new-service")

    # Assert
    mock_v1_net_api.read_namespaced_ingress.assert_called_once()
    mock_v1_net_api.patch_namespaced_ingress.assert_called_once()


@pytest.mark.asyncio
@patch("cactus_orchestrator.k8s.resource.delete.v1_core_api")
async def test_delete_service(mock_v1_core_api, mock_thread_cls):
    """Test deleting a Kubernetes Service."""
    # Arrange
    mock_v1_core_api.delete_namespaced_service.return_value = mock_thread_cls(None)

    # Act
    await delete_service("test-service")

    # Assert
    mock_v1_core_api.delete_namespaced_service.assert_called_once()


@pytest.mark.asyncio
@patch("cactus_orchestrator.k8s.resource.delete.v1_app_api")
async def test_delete_statefulset(mock_v1_app_api, mock_thread_cls):
    """Test deleting a Kubernetes StatefulSet."""
    # Arrange
    mock_v1_app_api.delete_namespaced_stateful_set.return_value = mock_thread_cls(None)

    # Act
    await delete_statefulset("test-statefulset")

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

    mock_v1_net_api.read_namespaced_ingress.return_value = mock_thread_cls(mock_ingress)
    mock_v1_net_api.patch_namespaced_ingress.return_value = mock_thread_cls(None)

    # Act
    await remove_ingress_rule("remove-me")

    # Assert
    mock_v1_net_api.read_namespaced_ingress.assert_called_once()
    mock_v1_net_api.patch_namespaced_ingress.assert_called_once()
    assert len(mock_ingress.spec.rules[0].http.paths) == 0
