import pytest
from fastapi.routing import iter_route_contexts
from fastapi.testclient import TestClient

from cactus_orchestrator.main import generate_app
from cactus_orchestrator.settings import get_current_settings


@pytest.mark.asyncio
async def test_endpoints_fail_without_auth():
    """Loop through all app routes and check security.
    NOTE: Documentation routes are left unsecured."""

    app = generate_app(get_current_settings())
    with TestClient(app) as client:
        checked = 0
        # FastAPI now lazily wraps included routers - iter_route_contexts flattens them into concrete routes
        for route in iter_route_contexts(app.routes):
            if route.name not in ("openapi", "swagger_ui_html", "swagger_ui_redirect", "redoc_html"):
                if route.methods:
                    for method in route.methods:
                        if method in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                            url = route.path
                            checked += 1

                            response = client.request(method, url)

                            assert response.status_code in [401, 403], f"Failed security check for {method} {url}"

        assert checked > 0, "No routes were checked"
