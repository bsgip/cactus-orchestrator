import unittest.mock as mock
from collections.abc import Callable, Generator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest
from assertical.asserts.type import assert_list_type
from assertical.fake.generator import generate_class_instance
from podman.domain.pods import Pod
from podman.errors import ImageNotFound, NotFound

from cactus_orchestrator.pod.manager import (
    create_pod_run,
    destroy_pod_resources,
    ensure_images,
    fetch_running_pods,
    get_podman_version,
)
from cactus_orchestrator.pod.models import PodImages, PodResources, PodRoutes, RunningPod


@dataclass(frozen=True)
class MockedPodmanClient:
    version: mock.Mock
    images_get: mock.Mock
    images_pull: mock.Mock
    volumes_create: mock.Mock
    volumes_get: mock.Mock
    pods_create: mock.Mock
    pods_get: mock.Mock
    pods_list: mock.Mock
    containers_run: mock.Mock
    containers_get: mock.Mock
    containers_render_payload: mock.Mock
    api_post: mock.Mock

    assert_client: Callable


@pytest.fixture()
def mock_client() -> Generator[MockedPodmanClient]:
    """mocks the _client function to return a mock. Returns a collection of all the mocked client API functions.

    Will assert that the client was used as part of a context manager"""
    with mock.patch("cactus_orchestrator.pod.manager._client") as mock_client_fn:
        mocked_client = mock.Mock(name="Client")
        mocked_client.__enter__ = mock.Mock(return_value=mocked_client)
        mocked_client.__exit__ = mock.Mock(return_value=None)

        def assert_client():
            # The mock should've been created AND used within a "with" block
            mock_client_fn.assert_called_once()
            mocked_client.__enter__.assert_called_once()
            mocked_client.__exit__.assert_called_once()

        all_mocks = MockedPodmanClient(
            mock.Mock(),
            mock.Mock(),
            mock.Mock(),
            mock.Mock(),
            mock.Mock(),
            mock.Mock(),
            mock.Mock(),
            mock.Mock(),
            mock.Mock(),
            mock.Mock(),
            mock.Mock(),
            mock.Mock(),
            assert_client,
        )

        mocked_client.version = all_mocks.version
        mocked_client.images = mock.Mock(name="client.images")
        mocked_client.images.get = all_mocks.images_get
        mocked_client.images.pull = all_mocks.images_pull
        mocked_client.volumes = mock.Mock(name="client.volumes")
        mocked_client.volumes.get = all_mocks.volumes_get
        mocked_client.volumes.create = all_mocks.volumes_create
        mocked_client.pods = mock.Mock(name="client.pods")
        mocked_client.pods.get = all_mocks.pods_get
        mocked_client.pods.create = all_mocks.pods_create
        mocked_client.pods.list = all_mocks.pods_list
        mocked_client.containers = mock.Mock(name="client.containers")
        mocked_client.containers.get = all_mocks.containers_get
        mocked_client.containers.run = all_mocks.containers_run
        mocked_client.containers._render_payload = all_mocks.containers_render_payload
        mocked_client.api = mock.Mock(name="client.api")
        mocked_client.api.post = all_mocks.api_post

        mock_client_fn.return_value = mocked_client

        yield all_mocks


@pytest.mark.parametrize(
    "raw_version, expected",
    [
        (Exception, Exception),
        ({}, Exception),
        ({"Version": None}, Exception),
        ({"Version": ""}, Exception),
        ({"Version": "1"}, (1, 0, 0)),
        ({"Version": "1.2"}, (1, 2, 0)),
        ({"Version": "1.2.3"}, (1, 2, 3)),
        ({"Version": "1.2.3.4"}, (1, 2, 3)),
        ({"Version": "1.2-foo.3"}, (1, 0, 3)),
    ],
)
async def test_get_version(
    mock_client: MockedPodmanClient, raw_version: dict | type[Exception], expected: tuple | type[Exception]
):
    """Tests that version can be parsed from podman into a clean tuple"""

    if isinstance(raw_version, dict):
        mock_client.version.return_value = raw_version
    else:
        mock_client.version.side_effect = raw_version("mock exception")

    if isinstance(expected, tuple):
        result = await get_podman_version("/fake/socket")
        assert isinstance(result, tuple)
        assert len(result) == 3
        assert result == expected
    else:
        with pytest.raises(expected):
            await get_podman_version("/fake/socket")

    mock_client.assert_client()


@pytest.mark.parametrize(
    "unpulled_images, pull_error_images, error",
    [
        ([], [], None),
        (["my/image/rabbitmq", "my/image/runner"], [], None),
        (["my/image/rabbitmq", "my/image/runner"], ["my/image/runner"], ImageNotFound),
        (
            ["my/image/postgres", "my/image/rabbitmq", "my/image/envoy", "my/image/runner", "my/image/init"],
            [],
            None,
        ),
    ],
)
async def test_ensure_images(
    mock_client: MockedPodmanClient,
    unpulled_images: list[str],
    pull_error_images: list[str],
    error: type[Exception] | None,
):
    """Tests that ensure images interacts with the API and can handle missing images"""
    # Arrange
    images = PodImages(
        csip_aus_version="v99",
        postgres="my/image/postgres",
        rabbitmq="my/image/rabbitmq",
        envoy="my/image/envoy",
        runner="my/image/runner",
        init="my/image/init",
    )
    ALL_IMAGES = [
        "my/image/postgres",
        "my/image/rabbitmq",
        "my/image/envoy",
        "my/image/runner",
        "my/image/init",
    ]

    def _image_get(image: str):
        if image in unpulled_images:
            raise ImageNotFound("this image is said to not exist")

        if image not in ALL_IMAGES:
            raise Exception("Mock error")

        return None

    def _image_pull(image: str):
        if image in pull_error_images:
            raise ImageNotFound("this image cannot be pulled")

        return None

    mock_client.images_pull.side_effect = _image_pull
    mock_client.images_get.side_effect = _image_get

    # Act
    if error is None:
        await ensure_images("/fake/sock", images)

        # Every image is fetched
        mock_client.images_get.assert_has_calls(
            [mock.call(i) for i in ALL_IMAGES],
            any_order=True,
        )

        # Every missing image is pulled
        mock_client.images_pull.assert_has_calls(
            [mock.call(i) for i in unpulled_images],
            any_order=True,
        )
    else:
        with pytest.raises(error):
            await ensure_images("/fake/sock", images)

    mock_client.assert_client()


@pytest.mark.parametrize(
    "pod_exists, pod_remove_error, volume_exists, volume_remove_error, expected_result",
    [
        (False, None, False, None, True),  # Nothing exists
        (True, None, True, None, True),  # Everything exists
        (True, None, False, None, True),  # Just pod
        (False, None, True, None, True),  # Just volume
        (True, Exception, False, None, False),  # Error on pod remove
        (False, None, True, Exception, False),  # Error on volume remove
        (True, None, True, Exception, False),  # Error on volume remove
    ],
)
async def test_destroy_pod_resources(
    mock_client: MockedPodmanClient,
    pod_exists: bool,
    pod_remove_error: type[Exception] | None,
    volume_exists: bool,
    volume_remove_error: type[Exception] | None,
    expected_result: bool,
):
    """Tests the various ways destroy pod will attempt to report on success/failure"""
    # Arrange
    resources = generate_class_instance(PodResources)

    mock_pod = mock.Mock()
    mock_pod.remove = mock.Mock()
    if pod_exists:
        mock_client.pods_get.return_value = mock_pod
    else:
        mock_client.pods_get.side_effect = NotFound("mock error")
    if pod_remove_error is not None:
        mock_pod.remove.side_effect = pod_remove_error("mock exc")

    mock_volume = mock.Mock()
    mock_volume.remove = mock.Mock()
    if volume_exists:
        mock_client.volumes_get.return_value = mock_volume
    else:
        mock_client.volumes_get.side_effect = NotFound("mock error")
    if volume_remove_error is not None:
        mock_volume.remove.side_effect = volume_remove_error("mock exc")

    # Act
    result = await destroy_pod_resources("/fake/socket", resources)

    # Assert
    assert isinstance(result, bool)
    assert result is expected_result

    mock_client.pods_get.assert_called_once_with(resources.pod_name)
    if not pod_remove_error:
        mock_client.volumes_get.assert_called_once_with(resources.volume_name)

    if pod_exists:
        mock_pod.remove.assert_called_once_with(force=True)
    if volume_exists and not pod_remove_error:
        mock_volume.remove.assert_called_once_with(force=True)

    mock_client.assert_client()


@pytest.mark.parametrize(
    "health_values",
    [
        [{"State": {"Health": {"Status": "HeAlThY"}}}],
        [{}, {"State": {"Health": {"Status": "not healthy"}}}, {"State": {"Health": {"Status": "hEALTHY"}}}],
    ],
)
async def test_create_pod_run_success(mock_client: MockedPodmanClient, health_values: list[dict]):
    """Does a successful startup behave as expected - and can handle health checks taking a bit to stabilise"""
    # Arrange
    images = generate_class_instance(PodImages, seed=101)
    routes = generate_class_instance(PodRoutes, seed=202)
    resources = generate_class_instance(PodResources, seed=303)

    mock_client.containers_render_payload.side_effect = lambda kwargs: kwargs

    # The container reload() will assign each value from health_values into the attrs element
    expected_health_check_count = len(health_values)
    mock_runner_container = mock.Mock()

    def reload_side_effect():
        mock_runner_container.attrs = health_values.pop(0)

    mock_runner_container.reload = mock.Mock(side_effect=reload_side_effect)
    mock_client.containers_get.return_value = mock_runner_container

    # We need to mock the low level runner API call
    runner_container_id = "abc-123"
    mock_resp = mock.Mock()
    mock_client.api_post.return_value = mock_resp
    mock_resp.json.return_value = {"Id": runner_container_id}

    # Plumb in a pod/volume removal (to ensure they don't get called)
    mock_pod = mock.Mock()
    mock_pod.remove = mock.Mock()
    mock_client.pods_get.return_value = mock_pod
    mock_volume = mock.Mock()
    mock_volume.remove = mock.Mock()
    mock_client.volumes_get.return_value = mock_volume

    # Act
    await create_pod_run("/fake/socket", images, resources, routes)

    # Assert

    # We created a shared volume / pod
    mock_client.volumes_create.assert_called_once_with(name=resources.volume_name)
    mock_client.pods_create.assert_has_calls(
        [mock.call(name=resources.pod_name, Networks=mock.ANY, userns=mock.ANY, labels=resources.pod_labels)]
    )

    # Our containers are created - noting that runner is created via low level API due to startup
    assert mock_client.containers_run.call_count == 6
    assert all([c.kwargs["detach"] is True for c in mock_client.containers_run.call_args_list]), (
        "Every container should run detached"
    )
    assert all([c.kwargs["pod"] == resources.pod_name for c in mock_client.containers_run.call_args_list]), (
        "Every container should run in pod"
    )

    # Count up the container creations - make sure they make sense
    # Also account for the low level API call for runner
    creation_by_image_name: dict[str, int] = {}
    for img_name in [c.args[0] for c in mock_client.containers_run.call_args_list]:
        existing = creation_by_image_name.get(img_name, None)
        if existing is None:
            creation_by_image_name[img_name] = 1
        else:
            creation_by_image_name[img_name] = existing + 1

    mock_client.containers_render_payload.assert_called_once()
    mock_client.api_post.assert_called_once()
    assert mock_client.containers_render_payload.call_args_list[0].args[0]["image"] == images.runner
    assert images.runner not in creation_by_image_name, (
        "This is because we are manually calling api_post instead of container.run"
    )
    creation_by_image_name[images.runner] = 1

    assert creation_by_image_name[images.envoy] == 3, "envoy, admin, taskiq-worker"
    assert creation_by_image_name[images.postgres] == 1
    assert creation_by_image_name[images.rabbitmq] == 1
    assert creation_by_image_name[images.init] == 1
    assert creation_by_image_name[images.runner] == 1

    assert mock_runner_container.reload.call_count == expected_health_check_count

    mock_pod.remove.assert_not_called()
    mock_volume.remove.assert_not_called()


async def test_fetch_running_pods(mock_client: MockedPodmanClient):
    # Arrange
    mock_client.pods_list.return_value = [
        Pod(
            attrs={
                "Containers": [],
                "Created": "2026-06-11T11:09:05.717943643+10:00",
                "Id": "17b61669f63b39f251b4deb3ac3b04609e9edda3933504280118fcabc6847988",
                "Name": "run-11",
                "Namespace": "",
                "Networks": ["cactus-net"],
                "Status": "Running",
                "Labels": {"cactus": "true", "cactus:run": "11", "cactus:run_group": "22"},
            }
        ),
        Pod(
            attrs={
                "Containers": [],
                "Created": "2026-05-10T01:02:03+00:00",
                "Id": "d9631e0019f949f1b31c04fdf2ae630d814215f45b0e45d88c9d231fad5811af",
                "Name": "run-22",
                "Namespace": "",
                "Networks": ["cactus-net"],
                "Status": "Stopped",
                "Labels": {"cactus": "true", "cactus:run": "22", "cactus:run_group": "33"},
            }
        ),
    ]

    # Act
    running_pods = await fetch_running_pods("/mock/sock.sock")

    # Assert
    assert_list_type(RunningPod, running_pods, count=2)

    assert running_pods[0].id == "17b61669f63b39f251b4deb3ac3b04609e9edda3933504280118fcabc6847988"
    assert running_pods[0].created_time == datetime(2026, 6, 11, 11, 9, 5, 717943, timezone(timedelta(hours=10)))
    assert running_pods[0].is_running is True
    assert running_pods[0].run_group_id == 22
    assert running_pods[0].run_id == 11
    assert running_pods[0].resources.pod_name == "run-11"

    assert running_pods[1].id == "d9631e0019f949f1b31c04fdf2ae630d814215f45b0e45d88c9d231fad5811af"
    assert running_pods[1].created_time == datetime(2026, 5, 10, 1, 2, 3, 0, timezone(timedelta(hours=0)))
    assert running_pods[1].is_running is False
    assert running_pods[1].run_group_id == 33
    assert running_pods[1].run_id == 22
    assert running_pods[1].resources.pod_name == "run-22"
