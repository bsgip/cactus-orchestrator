import json
from unittest.mock import AsyncMock, MagicMock, patch

import podman.errors as podman_errors
import pytest

import cactus_orchestrator.teststack.manager as teststack_manager
from cactus_orchestrator.settings import _reset_current_settings, get_current_settings
from cactus_orchestrator.teststack.manager import (
    _destroy_pod,
    _pod_name,
    destroy,
    get_resource_names,
    spawn,
)


@pytest.fixture(autouse=True)
def podman_settings(monkeypatch):
    monkeypatch.setenv("ORCHESTRATOR_DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
    monkeypatch.setenv("TEST_EXECUTION_FQDN", "cactus.test.local")
    monkeypatch.setenv(
        "PODMAN_TESTSTACK_IMAGES",
        json.dumps(
            {
                "1.0": {
                    "postgres": "postgres:16",
                    "pubsub": "rabbitmq:3",
                    "teststack-init": "init:test",
                    "envoy": "envoy:test",
                    "runner": "runner:test",
                }
            }
        ),
    )
    _reset_current_settings()
    yield
    _reset_current_settings()


def test_get_resource_names():
    names = get_resource_names("abc123-42")
    assert names.runner_base_url == "http://envoy-svc-abc123-42:8080"
    assert names.envoy_base_url == "https://cactus.test.local/envoy-svc-abc123-42"


def test_pod_name():
    assert _pod_name("abc123-42") == "envoy-svc-abc123-42"


@pytest.mark.asyncio
async def test_destroy_handles_not_found():
    with patch.object(teststack_manager, "_destroy_pod", side_effect=podman_errors.NotFound("pod", None)):
        await destroy("abc123-42")  # should not raise


@pytest.mark.asyncio
async def test_spawn_cleans_up_on_failure():
    with (
        patch.object(teststack_manager, "_create_pod_and_containers", side_effect=RuntimeError("disk full")),
        patch.object(teststack_manager, "destroy", new_callable=AsyncMock) as mock_destroy,
    ):
        with pytest.raises(RuntimeError):
            await spawn("abc123-42", "1.0", "test-user")
        mock_destroy.assert_awaited_once_with("abc123-42")


def _mock_client() -> tuple[MagicMock, MagicMock, dict[str, dict], dict]:
    """Context-manager mock for _client(); also the client mock, a dict capturing containers.run()
    kwargs by name, and the runner spec passed to the low-level create path."""
    runs: dict[str, dict] = {}
    runner_spec: dict = {}
    client = MagicMock()
    client.containers.run.side_effect = lambda _image, **kwargs: runs.__setitem__(kwargs["name"], kwargs)
    # The runner is created via _render_payload + a low-level POST, not containers.run.
    client.containers._render_payload.side_effect = lambda payload: (runner_spec.update(payload), dict(payload))[1]
    client.api.post.return_value.json.return_value = {"Id": "runner-id"}
    cm = MagicMock()
    cm.__enter__.return_value = client
    cm.__exit__.return_value = False
    return cm, client, runs, runner_spec


def test_pod_on_cactus_net_runner_public_internals_localhost():
    settings = get_current_settings()
    cm, client, runs, runner_spec = _mock_client()
    with patch.object(teststack_manager, "_client", return_value=cm):
        teststack_manager._create_pod_and_containers(
            "envoy-svc-abc123-42", settings.podman_teststack_images["1.0"], "/envoy-svc-abc123-42", "1.0", settings
        )

    # The pod joins cactus-net (so Traefik can discover it and the orchestrator can reach it by name).
    client.pods.create.assert_called_once()
    pod_kwargs = client.pods.create.call_args.kwargs
    assert pod_kwargs["name"] == "envoy-svc-abc123-42"
    assert set(pod_kwargs["Networks"]) == {settings.podman_network}

    # Every container (run-created internals + the low-level runner) is a member of the pod.
    for c in runs.values():
        assert c["pod"] == "envoy-svc-abc123-42"
    assert runner_spec["pod"] == "envoy-svc-abc123-42"

    # Traefik routing lives on the runner (the ingress), incl. the StripPrefix middleware.
    runner_labels = runner_spec["labels"]
    assert runner_labels["traefik.enable"] == "true"
    assert runner_labels["traefik.docker.network"] == settings.podman_network
    assert runner_labels["traefik.http.routers.envoy-svc-abc123-42.rule"] == "PathPrefix(`/envoy-svc-abc123-42`)"
    strip_key = "traefik.http.middlewares.envoy-svc-abc123-42-strip.stripprefix.prefixes"
    assert runner_labels[strip_key] == "/envoy-svc-abc123-42"
    assert runner_labels["traefik.http.services.envoy-svc-abc123-42.loadbalancer.server.port"] == "8080"

    # envoy stays internal — no labels at all (Traefik routes only to the runner).
    assert "labels" not in runs["envoy-svc-abc123-42-envoy"]

    # The internals bind localhost so other teststacks sharing cactus-net cannot reach them via the pod's
    # bridge IP; the runner sets no HOST and relies on the image's 0.0.0.0 default (it is the ingress).
    assert "HOST" not in runner_spec["environment"]
    assert runner_spec["environment"]["PORT"] == "8080"
    assert runs["envoy-svc-abc123-42-envoy"]["environment"]["HOST"] == "127.0.0.1"
    assert runs["envoy-svc-abc123-42-envoy-admin"]["environment"]["HOST"] == "127.0.0.1"

    # init writes the migration sentinel; the schema-dependent services block on it before starting.
    assert runs["envoy-svc-abc123-42-init"]["environment"]["MIGRATION_SENTINEL"] == "/shared/migrations.ready"
    assert runs["envoy-svc-abc123-42-envoy"]["environment"]["MIGRATION_SENTINEL"] == "/shared/migrations.ready"

    # The runner is created through the low-level path (v4 startup-healthcheck workaround) and started.
    client.api.post.assert_called_once()
    client.containers.get.return_value.start.assert_called_once()


def test_destroy_removes_pod_and_volume():
    client = MagicMock()
    cm = MagicMock()
    cm.__enter__.return_value = client
    cm.__exit__.return_value = False
    with patch.object(teststack_manager, "_client", return_value=cm):
        _destroy_pod("envoy-svc-abc123-42")

    client.pods.get.assert_called_once_with("envoy-svc-abc123-42")
    client.pods.get.return_value.stop.assert_called_once()
    client.pods.get.return_value.remove.assert_called_once_with(force=True)
    client.volumes.get.assert_called_once_with("envoy-svc-abc123-42-shared")
