import pytest
from fastapi.testclient import TestClient

from cactus_orchestrator.main import app


@pytest.mark.asyncio
async def test_endpoints_fail_without_auth():
    """Loop through all app routes and check security.
    NOTE: Documentation routes are left unsecured."""
    with TestClient(app) as client:
        for route in app.routes:
            if route.name not in ("openapi", "swagger_ui_html", "swagger_ui_redirect", "redoc_html"):  # ty:ignore[unresolved-attribute]
                if hasattr(route, "methods"):
                    for method in route.methods:  # ty:ignore[not-iterable]
                        if method in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                            url = route.path  # ty:ignore[unresolved-attribute]

                            response = client.request(method, url)

                            assert response.status_code in [401, 403], f"Failed security check for {method} {url}"
