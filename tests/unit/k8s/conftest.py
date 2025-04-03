from typing import Generator
import pytest


class MockThread:
    """For async_req=True in Kubernetes API calls - it doesn't actually support asyncio"""

    def __init__(self, result):
        self.result = result

    def get(self, *args, **kwargs):
        return self.result


@pytest.fixture(scope="function")
def mock_thread_cls() -> Generator[type[MockThread], None, None]:
    yield MockThread
