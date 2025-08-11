from unittest.mock import Mock, patch

import pytest
from kubernetes.client.exceptions import ApiException

from cactus_orchestrator.k8s.resource import (
    RunResourceNames,
    TemplateResourceNames,
    async_k8s_api_retry,
    get_resource_names,
    get_template_names,
)
from cactus_orchestrator.settings import CactusOrchestratorException


@pytest.mark.asyncio
async def test_async_k8s_api_retry_success():
    """Test that async_k8s_api_retry succeeds on the first attempt."""

    @async_k8s_api_retry()
    async def sample_function():
        return "success"

    result = await sample_function()
    assert result == "success"


@pytest.mark.asyncio
async def test_async_k8s_api_retry_takes_args():
    """Test that async_k8s_api_retry takes args and kwargs."""

    @async_k8s_api_retry()
    async def arg_function(arg, kwarg="kwarg0"):
        return arg, kwarg

    result = await arg_function("hi", kwarg="kwarg1")
    assert result[0] == "hi"
    assert result[1] == "kwarg1"


@pytest.mark.asyncio
async def test_async_k8s_api_retry_retries_then_succeeds():
    """Test that async_k8s_api_retry retries and eventually succeeds."""
    attempts = 0

    @async_k8s_api_retry(retries=3, delay=0)
    async def sample_function():
        nonlocal attempts
        attempts += 1
        if attempts < 2:
            raise ApiException(status=500, reason="Internal Server Error")
        return "success"

    result = await sample_function()
    assert result == "success"
    assert attempts == 2


@pytest.mark.asyncio
async def test_async_k8s_api_retry_exceeds_retries():
    """Test that async_k8s_api_retry raises an exception after max retries."""

    @async_k8s_api_retry(retries=2, delay=0)
    async def sample_function():
        raise ApiException(status=500, reason="Internal Server Error")

    with pytest.raises(CactusOrchestratorException, match="Failed action: sample_function"):
        await sample_function()


@pytest.mark.asyncio
async def test_async_k8s_api_retry_ignore_status_code():
    """Test that async_k8s_api_retry ignores a specified status code."""

    @async_k8s_api_retry(ignore_status_code=404)
    async def sample_function():
        raise ApiException(status=404, reason="Not Found")

    result = await sample_function()
    assert result is None


@pytest.mark.asyncio
async def test_async_k8s_api_retry_fail_silently():
    """Test that async_k8s_api_retry logs but does not raise an exception when fail_silently=True."""

    @async_k8s_api_retry(fail_silently=True)
    async def sample_function():
        raise ApiException(status=500, reason="Internal Server Error")

    result = await sample_function()
    assert result is None


@patch("cactus_orchestrator.k8s.resource.get_current_settings")
def test_get_template_names(mock_get_current_settings):
    """Test get_resource_names function."""
    mock_settings = Mock()
    mock_settings.test_execution_namespace = "other-ns"
    mock_settings.teststack_templates_namespace = "test-ns"
    mock_settings.template_service_name_prefix = "template-service-"
    mock_settings.template_statefulset_name_prefix = "template-statefulset-"
    mock_settings.template_app_name_prefix = "template-app-"
    mock_get_current_settings.return_value = mock_settings

    version = "v-456"
    names = get_template_names(version)
    assert isinstance(names, TemplateResourceNames)

    all_name_values = list(names.__dict__.values())
    assert len(all_name_values) == len(set(all_name_values)), "All names should be unique"

    assert names.namespace == "test-ns"
    assert version in names.service and names.service.startswith("template-service-")
    assert version in names.stateful_set and names.stateful_set.startswith("template-statefulset-")
    assert version in names.app_label and names.app_label.startswith("template-app-")

    assert names == get_template_names(version), "Same inputs - same output"
    assert names != get_template_names(version + "a")


@patch("cactus_orchestrator.k8s.resource.get_current_settings")
def test_get_resource_names(mock_get_current_settings):
    """Test get_resource_names function."""
    mock_settings = Mock()
    mock_settings.test_execution_namespace = "test-ns"
    mock_settings.teststack_templates_namespace = "other-ns"
    mock_settings.template_service_name_prefix = "template-service-"
    mock_settings.template_statefulset_name_prefix = "template-statefulset-"
    mock_settings.template_app_name_prefix = "template-app-"
    mock_get_current_settings.return_value = mock_settings

    uuid = "abc123"
    names = get_resource_names(uuid)
    assert isinstance(names, RunResourceNames)

    all_name_values = list(names.__dict__.values())
    assert len(all_name_values) == len(set(all_name_values)), "All names should be unique"

    assert names.namespace == "test-ns"
    assert uuid in names.service and names.service.startswith("template-service-")
    assert uuid in names.stateful_set and names.stateful_set.startswith("template-statefulset-")
    assert uuid in names.app_label and names.app_label.startswith("template-app-")
    assert uuid in names.pod
    assert uuid in names.pod_fqdn

    # Some rudimentary checks on a hostname
    assert names.pod_fqdn.lower() == names.pod_fqdn
    assert "/" not in names.pod_fqdn
    assert ":" not in names.pod_fqdn

    # Should vary based on inputs
    assert names == get_resource_names(uuid), "Same inputs - same output"
    assert names != get_resource_names(uuid + "a")
