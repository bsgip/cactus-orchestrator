from dataclasses import dataclass
from unittest.mock import Mock


@dataclass
class MockedK8s:
    # create
    add_ingress_rule: Mock
    clone_service: Mock
    clone_statefulset: Mock
    wait_for_pod: Mock

    # delete
    delete_service: Mock
    delete_statefulset: Mock
    remove_ingress_rule: Mock

    # RunnerClient
    init: Mock
    start: Mock
    finalize: Mock
    status: Mock
    health: Mock
    last_interaction: Mock
