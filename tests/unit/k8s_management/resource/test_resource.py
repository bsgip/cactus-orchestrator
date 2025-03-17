"""TODO: Migrate to modern asyncio-compatible + typed kubernetes library"""

from unittest.mock import patch

import pytest
from kubernetes import client

from cactus.harness_orchestrator.settings import DEFAULT_INGRESS_PATH_FORMAT
from cactus.harness_orchestrator.k8s_management.resource.create import (
    clone_service,
    clone_statefulset,
    is_container_ready,
    wait_for_pod,
    add_ingress_rule,
)
from cactus.harness_orchestrator.k8s_management.resource.delete import (
    remove_ingress_rule,
    delete_service,
    delete_statefulset,
)


class MockThread:
    """For async_req=True in Kubernetes API calls - it doesn't actually support asyncio"""

    def __init__(self, result):
        self.result = result

    def get(self, *args, **kwargs):
        return self.result


@pytest.mark.asyncio
@patch("cactus.harness_orchestrator.k8s_management.resource.create.v1_core_api")
async def test_clone_service(mock_v1_core_api):
    # Arrange
    mock_service = client.V1Service(
        api_version="v1",
        kind="Service",
        metadata=client.V1ObjectMeta(name="template-service"),
        spec=client.V1ServiceSpec(ports=[client.V1ServicePort(port=80)]),
    )

    mock_v1_core_api.read_namespaced_service.return_value = MockThread(mock_service)
    mock_v1_core_api.create_namespaced_service.return_value = MockThread(None)

    # Act
    await clone_service("new-service", "new-app-label")

    # Assert
    mock_v1_core_api.read_namespaced_service.assert_called_once()
    mock_v1_core_api.create_namespaced_service.assert_called_once()


@pytest.mark.asyncio
@patch("cactus.harness_orchestrator.k8s_management.resource.create.v1_app_api")
async def test_clone_statefulset(mock_v1_app_api):
    """Test cloning a Kubernetes StatefulSet."""
    mock_statefulset = client.V1StatefulSet(
        api_version="apps/v1",
        kind="StatefulSet",
        metadata=client.V1ObjectMeta(name="template-statefulset"),
        spec=client.V1StatefulSetSpec(
            service_name="template-service",
            selector=client.V1LabelSelector(match_labels={"app": "template-app"}),
            template=client.V1PodTemplateSpec(metadata=client.V1ObjectMeta(labels={"app": "template-app"})),
        ),
    )

    mock_v1_app_api.read_namespaced_stateful_set.return_value = MockThread(mock_statefulset)
    mock_v1_app_api.create_namespaced_stateful_set.return_value = MockThread(None)

    await clone_statefulset("new-statefulset", "new-service", "new-app-label")

    mock_v1_app_api.read_namespaced_stateful_set.assert_called_once()
    mock_v1_app_api.create_namespaced_stateful_set.assert_called_once()


@pytest.mark.asyncio
@patch("cactus.harness_orchestrator.k8s_management.resource.create.v1_core_api")
async def test_is_container_ready(mock_v1_core_api, generate_k8s_class_instance):
    """Test checking if a container is ready."""
    # Arrange
    mock_pod = client.V1Pod(
        status=client.V1PodStatus(
            container_statuses=[
                generate_k8s_class_instance(client.V1ContainerStatus, name="envoy-db", ready=True),
                generate_k8s_class_instance(client.V1ContainerStatus, name="blah", ready=True),
            ]
        )
    )
    mock_v1_core_api.read_namespaced_pod.return_value = MockThread(mock_pod)

    # Act
    res = await is_container_ready("test-pod")

    # Assert
    mock_v1_core_api.read_namespaced_pod.assert_called_once()
    assert res == True


@pytest.mark.asyncio
@patch("cactus.harness_orchestrator.k8s_management.resource.create.v1_core_api")
async def test_is_container_ready_not_found(mock_v1_core_api):
    """Test checking container readiness when the container is missing."""
    # Arrange
    mock_pod = client.V1Pod(status=client.V1PodStatus(container_statuses=[]))

    mock_v1_core_api.read_namespaced_pod.return_value = MockThread(mock_pod)

    # Act
    res = await is_container_ready("test-pod")

    # Assert
    assert res == False


@pytest.mark.asyncio
@patch("cactus.harness_orchestrator.k8s_management.resource.create.is_container_ready", return_value=True)
async def test_wait_for_pod(mock_is_container_ready):
    """Test waiting for a pod to be ready."""
    await wait_for_pod("test-pod")
    mock_is_container_ready.assert_called_once()


@pytest.mark.asyncio
@patch("cactus.harness_orchestrator.k8s_management.resource.create.v1_net_api")
async def test_add_ingress_rule(mock_v1_net_api):
    """Test adding an ingress rule to Kubernetes."""
    # Arrange
    mock_ingress = client.V1Ingress(
        spec=client.V1IngressSpec(rules=[client.V1IngressRule(http=client.V1HTTPIngressRuleValue(paths=[]))])
    )

    mock_v1_net_api.read_namespaced_ingress.return_value = MockThread(mock_ingress)
    mock_v1_net_api.patch_namespaced_ingress.return_value = MockThread(None)

    # Act
    await add_ingress_rule("new-service")

    # Assert
    mock_v1_net_api.read_namespaced_ingress.assert_called_once()
    mock_v1_net_api.patch_namespaced_ingress.assert_called_once()


@pytest.mark.asyncio
@patch("cactus.harness_orchestrator.k8s_management.resource.delete.v1_core_api")
async def test_delete_service(mock_v1_core_api):
    """Test deleting a Kubernetes Service."""
    # Arrange
    mock_v1_core_api.delete_collection_namespaced_service.return_value = MockThread(None)

    # Act
    await delete_service("test-service")

    # Assert
    mock_v1_core_api.delete_collection_namespaced_service.assert_called_once()


@pytest.mark.asyncio
@patch("cactus.harness_orchestrator.k8s_management.resource.delete.v1_app_api")
async def test_delete_statefulset(mock_v1_app_api):
    """Test deleting a Kubernetes StatefulSet."""
    # Arrange
    mock_v1_app_api.delete_namespaced_stateful_set.return_value = MockThread(None)

    # Act
    await delete_statefulset("test-statefulset")

    # Assert
    mock_v1_app_api.delete_namespaced_stateful_set.assert_called_once()


@pytest.mark.asyncio
@patch("cactus.harness_orchestrator.k8s_management.resource.delete.v1_net_api")
async def test_remove_ingress_rule(mock_v1_net_api, generate_k8s_class_instance):
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

    mock_v1_net_api.read_namespaced_ingress.return_value = MockThread(mock_ingress)
    mock_v1_net_api.patch_namespaced_ingress.return_value = MockThread(None)

    # Act
    await remove_ingress_rule("remove-me")

    # Assert
    mock_v1_net_api.read_namespaced_ingress.assert_called_once()
    mock_v1_net_api.patch_namespaced_ingress.assert_called_once()
    assert len(mock_ingress.spec.rules[0].http.paths) == 0
