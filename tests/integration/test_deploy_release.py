from datetime import UTC, datetime, timedelta
from http import HTTPStatus

import pytest
from assertical.fixtures.postgres import generate_async_session
from cactus_schema.orchestrator import DeployReleaseResponse

from cactus_orchestrator.api.deploy_release import DEPLOY_RELEASE_LIMIT
from cactus_orchestrator.model import DeployRelease


async def insert_deploy_releases(pg_config, tags_and_times: list[tuple[str, datetime]]) -> None:
    async with generate_async_session(pg_config) as session:
        for release_tag, created_at in tags_and_times:
            session.add(DeployRelease(release_tag=release_tag, created_at=created_at))
        await session.commit()


@pytest.mark.asyncio
async def test_fetch_deploy_releases_empty(client, pg_base_config, valid_jwt_user1):
    """A never-deployed environment returns an empty list"""

    # Act
    res = await client.get("/deploy_release", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    assert res.json() == []


@pytest.mark.asyncio
async def test_fetch_deploy_releases_orders_by_deploy_time(client, pg_base_config, valid_jwt_user1):
    # Arrange
    base = datetime(2026, 8, 1, tzinfo=UTC)
    await insert_deploy_releases(
        pg_base_config,
        [
            ("175", base),
            ("176", base + timedelta(hours=1)),
            ("177", base + timedelta(hours=2)),
            ("176", base + timedelta(hours=3)),  # Rollback
        ],
    )

    # Act
    res = await client.get("/deploy_release", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    data = DeployReleaseResponse.from_list(res.json())
    assert [d.release_tag for d in data] == ["176", "177", "176", "175"]
    assert data[0].created_at == base + timedelta(hours=3)


@pytest.mark.asyncio
async def test_fetch_deploy_releases_limits_to_most_recent(client, pg_base_config, valid_jwt_user1):

    # Arrange
    base = datetime(2026, 8, 1, tzinfo=UTC)
    total = DEPLOY_RELEASE_LIMIT + 5
    await insert_deploy_releases(pg_base_config, [(str(i), base + timedelta(hours=i)) for i in range(total)])

    # Act
    res = await client.get("/deploy_release", headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    # Assert
    assert res.status_code == HTTPStatus.OK
    data = DeployReleaseResponse.from_list(res.json())
    assert len(data) == DEPLOY_RELEASE_LIMIT
    assert [d.release_tag for d in data] == [str(i) for i in range(total - 1, total - 1 - DEPLOY_RELEASE_LIMIT, -1)]


@pytest.mark.asyncio
async def test_fetch_deploy_releases_requires_auth(client, pg_base_config):
    res = await client.get("/deploy_release")
    assert res.status_code == HTTPStatus.UNAUTHORIZED
