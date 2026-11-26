import pytest
from assertical.fake.generator import generate_class_instance
from assertical.fixtures.postgres import generate_async_session
from fastapi.exceptions import HTTPException

from cactus_orchestrator.api.common import (
    map_run_to_run_response,
    select_user_certificate_or_raise,
    select_user_run_group_or_raise,
    select_user_run_group_run_or_raise,
)
from cactus_orchestrator.auth import AuthPerm, UserContext
from cactus_orchestrator.model import Certificate, Run, RunGroup, User
from cactus_orchestrator.pod.models import PodRoutes
from cactus_orchestrator.settings import get_current_settings

admin_user_context = UserContext(subject_id="", issuer_id="", permissions=[AuthPerm.admin_all, AuthPerm.user_all])
user_1_context = UserContext(
    subject_id="user1", issuer_id="https://test-cactus-issuer.example.com", permissions=[AuthPerm.user_all]
)
user_2_context = UserContext(
    subject_id="user2", issuer_id="https://test-cactus-issuer.example.com", permissions=[AuthPerm.user_all]
)
user_3_context = UserContext(
    subject_id="user3", issuer_id="https://test-cactus-issuer.example.com", permissions=[AuthPerm.user_all]
)
non_existent_user_context = UserContext(
    subject_id="DNE", issuer_id="https://test-cactus-issuer.example.com", permissions=[AuthPerm.user_all]
)


@pytest.mark.parametrize(
    "run_group_id, user_context, user_id",
    [
        (1, user_1_context, 1),  # user 1 run group 1
        (2, user_1_context, 1),  # user 1 run group 2
        (3, user_2_context, 2),  # user 2 run group 3
    ],
)
@pytest.mark.asyncio
async def test_select_user_run_group_or_raise(
    run_group_id: int, user_context: UserContext, user_id: int, pg_base_config
):
    async with generate_async_session(pg_base_config) as session:
        user, run_group = await select_user_run_group_or_raise(
            session=session, user_context=user_context, run_group_id=run_group_id
        )
        assert isinstance(user, User)
        assert user.user_id == user_id
        assert isinstance(run_group, RunGroup)


@pytest.mark.parametrize(
    "run_group_id, user_context",
    [
        (3, user_1_context),  # user 1 can't access run_group 3
        (1, user_2_context),  # user 2 can't access run_group 1
        (4, admin_user_context),  # there is no run_group 4
    ],
)
@pytest.mark.asyncio
async def test_select_user_run_group_or_raise__raises_exception(
    run_group_id: int, user_context: UserContext, pg_base_config
):

    async with generate_async_session(pg_base_config) as session:
        with pytest.raises(HTTPException):
            _ = await select_user_run_group_or_raise(
                session=session, user_context=user_context, run_group_id=run_group_id
            )


@pytest.mark.parametrize(
    "user_context, certificate_id, user_id, expected_run_group_ids",
    [
        (user_1_context, 1, 1, [1]),
        (user_1_context, 3, 1, []),
        (user_2_context, 2, 2, [3]),
    ],
)
@pytest.mark.parametrize("for_update", [True, False])
@pytest.mark.asyncio
async def test_select_user_certificate_or_raise(
    user_context: UserContext,
    certificate_id: int,
    user_id: int,
    expected_run_group_ids: list[int],
    for_update: bool,
    pg_base_config,
):
    async with generate_async_session(pg_base_config) as session:
        user, certificate = await select_user_certificate_or_raise(session, user_context, certificate_id, for_update)
        assert isinstance(user, User)
        assert user.user_id == user_id
        assert isinstance(certificate, Certificate)
        assert certificate.certificate_id == certificate_id
        assert certificate.user_id == user_id
        assert [rg.run_group_id for rg in certificate.run_groups] == expected_run_group_ids


@pytest.mark.parametrize(
    "user_context, certificate_id",
    [
        (user_1_context, 2),  # belongs to user 2
        (user_2_context, 1),  # belongs to user 1
        (user_1_context, 99),  # doesn't exist
        (non_existent_user_context, 1),  # user doesn't exist
    ],
)
@pytest.mark.asyncio
async def test_select_user_certificate_or_raise__raises_exception(
    user_context: UserContext, certificate_id: int, pg_base_config
):
    async with generate_async_session(pg_base_config) as session:
        with pytest.raises(HTTPException):
            _ = await select_user_certificate_or_raise(session, user_context, certificate_id)


@pytest.mark.parametrize(
    "run_id, user_context, user_id",
    [
        (1, user_1_context, 1),  # user 1 run group 1 run 1
        (5, user_1_context, 1),  # user 1 run group 2 run 5
        (6, user_2_context, 2),  # user 2 run group 3 run 6
    ],
)
@pytest.mark.asyncio
async def test_select_user_run_group_run_or_raise(run_id: int, user_context: UserContext, user_id: int, pg_base_config):
    async with generate_async_session(pg_base_config) as session:
        user, run_group, run = await select_user_run_group_run_or_raise(
            session=session, user_context=user_context, run_id=run_id
        )
        assert isinstance(user, User)
        assert user.user_id == user_id
        assert isinstance(run_group, RunGroup)
        assert run_group.run_group_id == run.run_group_id
        assert isinstance(run, Run)
        assert run.run_id == run_id


@pytest.mark.parametrize(
    "run_id, user_context",
    [
        (99, user_1_context),  # run 99 DNE
        (6, user_1_context),  # user 1 can't access run_group 3
        (1, user_2_context),  # user 2 can't access run_group 1
    ],
)
@pytest.mark.asyncio
async def test_select_user_run_group_run_or_raise_raises_exception(
    run_id: int, user_context: UserContext, pg_base_config
):
    async with generate_async_session(pg_base_config) as session:
        with pytest.raises(HTTPException):
            _ = await select_user_run_group_run_or_raise(session=session, user_context=user_context, run_id=run_id)


@pytest.mark.parametrize(
    "run_warnings",
    [
        None,  # not yet finalised - unknown
        [],  # finalised, no warnings raised
        [
            {
                "type": "der-settings.set-max-w-varied",
                "description": "d",
                "message": "m",
                "timestamp": "2026-01-01T00:00:00+00:00",
            }
        ],
    ],
)
def test_map_run_to_run_response_warnings(run_warnings: list[dict] | None):
    run = generate_class_instance(Run, warnings=run_warnings)
    pod_routes = generate_class_instance(PodRoutes)
    settings = get_current_settings()

    response = map_run_to_run_response(settings, run, pod_routes)

    if run_warnings is None:
        assert response.warnings is None
    else:
        assert response.warnings is not None
        assert len(response.warnings) == len(run_warnings)
