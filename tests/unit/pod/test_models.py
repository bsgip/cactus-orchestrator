import pytest
from assertical.fake.generator import generate_class_instance

from cactus_orchestrator.model import Run, RunGroup
from cactus_orchestrator.pod.models import DEV_RUNNER_PORT_RANGE, PodResources, PodRoutes, dev_runner_localhost_port


@pytest.mark.parametrize("is_static_uri", [True, False])
def test_from_run_without_dev_port_base_uses_pod_dns(is_static_uri: bool):
    run = generate_class_instance(Run, run_id=11, run_group_id=22, pod_name=None)
    run_group = generate_class_instance(RunGroup, is_static_uri=is_static_uri, certificate_pem=bytes([1]))
    resources = PodResources.from_run("cactus-net", run)

    routes = PodRoutes.from_run("cactus.example.com", "/envoy", 8080, resources, run_group, run)

    assert routes.internal_base_url == "http://run-11:8080"
    assert routes.dev_host_port is None


@pytest.mark.parametrize("is_static_uri", [True, False])
def test_from_run_with_dev_port_base_uses_localhost(is_static_uri: bool):
    run = generate_class_instance(Run, run_id=11, run_group_id=22, pod_name=None)
    run_group = generate_class_instance(RunGroup, is_static_uri=is_static_uri, certificate_pem=bytes([1]))
    resources = PodResources.from_run("cactus-net", run)

    routes = PodRoutes.from_run(
        "cactus.example.com", "/envoy", 8080, resources, run_group, run, dev_localhost_port_base=20000
    )

    assert routes.dev_host_port is not None
    assert 20000 <= routes.dev_host_port < 20000 + DEV_RUNNER_PORT_RANGE
    assert routes.internal_base_url == f"http://127.0.0.1:{routes.dev_host_port}"

    # Everything unrelated to runner addressing must be identical to the production path
    prod_routes = PodRoutes.from_run("cactus.example.com", "/envoy", 8080, resources, run_group, run)
    assert routes.external_host == prod_routes.external_host
    assert routes.href_prefix == prod_routes.href_prefix
    assert routes.exposed_port == prod_routes.exposed_port


def test_dev_runner_localhost_port_deterministic_on_pod_name():
    assert dev_runner_localhost_port(20000, "run-11") == dev_runner_localhost_port(20000, "run-11")
    assert dev_runner_localhost_port(20000, "run-11") != dev_runner_localhost_port(20000, "run-12")

    shared_pod_run_a = generate_class_instance(Run, seed=1, run_id=11, run_group_id=22, pod_name="shared-pod")
    shared_pod_run_b = generate_class_instance(Run, seed=2, run_id=99, run_group_id=22, pod_name="shared-pod")
    run_group = generate_class_instance(RunGroup, is_static_uri=True, certificate_pem=bytes([1]))

    routes_a = PodRoutes.from_run(
        "cactus.example.com",
        "/envoy",
        8080,
        PodResources.from_run("cactus-net", shared_pod_run_a),
        run_group,
        shared_pod_run_a,
        dev_localhost_port_base=20000,
    )
    routes_b = PodRoutes.from_run(
        "cactus.example.com",
        "/envoy",
        8080,
        PodResources.from_run("cactus-net", shared_pod_run_b),
        run_group,
        shared_pod_run_b,
        dev_localhost_port_base=20000,
    )
    assert routes_a.internal_base_url == routes_b.internal_base_url
