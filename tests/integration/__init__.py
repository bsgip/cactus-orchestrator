from dataclasses import dataclass
from unittest.mock import AsyncMock, Mock


@dataclass
class MockedTeststack:
    # Podman teststack lifecycle
    spawn: AsyncMock
    destroy: AsyncMock

    # RunnerClient
    init: Mock
    start: Mock
    finalize: Mock
    status: Mock
    health: Mock
    last_interaction: Mock
    list_requests: Mock
    get_request: Mock
    proceed: Mock


# Backward-compat alias so any file that still imports MockedK8s keeps working
MockedK8s = MockedTeststack
