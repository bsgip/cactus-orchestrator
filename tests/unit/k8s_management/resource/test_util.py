import pytest
from unittest.mock import patch
from kubernetes.client.exceptions import ApiException

from cactus_orchestrator.k8s.resource import async_k8s_api_retry, get_resource_names
from cactus_orchestrator.settings import HarnessOrchestratorException


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

    with pytest.raises(HarnessOrchestratorException, match="Failed action: sample_function"):
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


@patch("cactus_orchestrator.k8s.resource.main_settings")
def test_get_resource_names(mock_settings):
    """Test get_resource_names function."""
    mock_settings.testing_namespace = "test-ns"
    mock_settings.template_service_name = "template-service"
    mock_settings.template_statefulset_name = "template-statefulset"
    mock_settings.template_app_name = "template-app"

    uuid = "abc123"
    svc_name, statefulset_name, app_label, pod_name, pod_fqdn = get_resource_names(uuid)

    assert svc_name == f"template-service-{uuid}"
    assert statefulset_name == f"template-statefulset-{uuid}"
    assert app_label == f"template-app-{uuid}"
    assert pod_name == f"{statefulset_name}-0"
    assert pod_fqdn == f"{pod_name}.{svc_name}.test-ns.svc.cluster.local"
