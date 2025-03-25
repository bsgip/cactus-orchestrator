from typing import Generator

import pytest
from fastapi.testclient import TestClient

from cactus_orchestrator.main import app


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    yield TestClient(app)


@pytest.mark.asyncio
async def test_endpoints_fail_without_auth(client):
    """Loop through all app routes and check security.
    NOTE: Documentation routes are left unsecured."""
    count = 0
    for route in app.routes:
        if route.name not in ("openapi", "swagger_ui_html", "swagger_ui_redirect", "redoc_html"):
            if hasattr(route, "methods"):
                for method in route.methods:
                    if method in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                        url = route.path

                        response = client.request(method, url)

                        assert response.status_code in [401, 403], f"Failed security check for {method} {url}"
