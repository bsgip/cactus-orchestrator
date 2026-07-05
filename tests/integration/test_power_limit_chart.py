"""
Integration tests for power_limit_chart.generate_power_limit_chart_html.

Each test builds a realistic DB scenario, generates the HTML chart, and writes it
to /tmp/cactus_charts/ so it can be opened in a browser for visual inspection.

Run with:
    pytest tests/integration/test_power_limit_chart.py -v -s
"""

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from http import HTTPStatus
from itertools import product
from pathlib import Path

import pytest
from assertical.asserts.generator import assert_class_instance_equality
from assertical.fake.generator import clone_class_instance, generate_class_instance
from assertical.fixtures.postgres import generate_async_session
from cactus_schema.runner.schema import HTTPMethod, RequestEntry
from envoy.server.model.archive.doe import (
    ArchiveDynamicOperatingEnvelope,
    ArchiveSiteControlGroupDefault,
)
from envoy.server.model.doe import (
    DynamicOperatingEnvelope,
    SiteControlGroup,
    SiteControlGroupDefault,
)
from envoy.server.model.site import Site, SiteDERSetting
from envoy.server.model.subscription import Subscription, SubscriptionResource
from sqlalchemy import text

from cactus_orchestrator.power_limit_chart import generate_power_limit_chart_html
from cactus_orchestrator.power_limit_chart.db import (
    _check_has_storage_target,
    _get_control_groups,
    _get_defaults,
    _get_der_setting,
    _get_does,
    _get_subscribed_group_ids,
    _RawControlGroup,
    _RawDefault,
    _RawDOE,
)
from cactus_orchestrator.power_limit_chart.limits import (
    _get_effective_lower_at,
    _get_effective_upper_at,
)
from cactus_orchestrator.power_limit_chart.replay import (
    _FAR_FUTURE,
    _Known,
    _KnownControlSegment,
)

OUTPUT_DIR = Path("/tmp/cactus_charts")

T0 = datetime(2026, 2, 26, 9, 30, 0, tzinfo=UTC)  # Test start time


def _out(name: str) -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    return OUTPUT_DIR / name


def _poll(group_id: int, when: datetime, req_id: int = 0, step_name: str = "") -> RequestEntry:
    """Construct a fake DERControl list poll request."""
    return RequestEntry(
        url=f"https://envoy.example.com/edev/1/derp/{group_id}/derc",
        path=f"/edev/1/derp/{group_id}/derc",
        method=HTTPMethod.GET,
        status=HTTPStatus.OK,
        timestamp=when,
        step_name=step_name,
        body_xml_errors=[],
        request_id=req_id,
    )


def _dderc_poll(group_id: int, when: datetime, req_id: int = 0, step_name: str = "") -> RequestEntry:
    """Construct a fake DefaultDERControl poll request."""
    return RequestEntry(
        url=f"https://envoy.example.com/edev/1/derp/{group_id}/dderc",
        path=f"/edev/1/derp/{group_id}/dderc",
        method=HTTPMethod.GET,
        status=HTTPStatus.OK,
        timestamp=when,
        step_name=step_name,
        body_xml_errors=[],
        request_id=req_id,
    )


def _make_doe(
    site: Site,
    group: SiteControlGroup,
    offset_minutes: float,
    duration_minutes: float,
    *,
    export_limit: Decimal | None = None,
    import_limit: Decimal | None = None,
    gen_limit: Decimal | None = None,
    load_limit: Decimal | None = None,
    ramp_time_seconds: Decimal | None = None,
    set_connected: bool | None = None,
    set_energized: bool | None = None,
    seed: int = 1,
) -> DynamicOperatingEnvelope:
    start = T0 + timedelta(minutes=offset_minutes)
    duration = int(duration_minutes * 60)
    end = start + timedelta(seconds=duration)
    return generate_class_instance(
        DynamicOperatingEnvelope,
        seed=seed,
        site=site,
        site_control_group=group,
        calculation_log_id=None,
        start_time=start,
        end_time=end,
        duration_seconds=duration,
        created_time=start - timedelta(seconds=30),
        changed_time=start - timedelta(seconds=30),
        export_limit_watts=export_limit,
        import_limit_active_watts=import_limit,
        generation_limit_active_watts=gen_limit,
        load_limit_active_watts=load_limit,
        ramp_time_seconds=ramp_time_seconds,
        set_connected=set_connected,
        superseded=False,
        set_energized=set_energized,
        set_point_percentage=None,
        randomize_start_seconds=None,
        storage_target_active_watts=None,
    )


def _make_site_with_setting(aggregator_id: int, max_w: int = 10000, grad_w: int = 28, seed: int = 1) -> Site:
    """Build a Site with one SiteDERSetting."""
    der_setting = generate_class_instance(
        SiteDERSetting,
        seed=seed,
        site_der_setting_id=None,
        site_id=None,
        max_w_value=max_w,
        max_w_multiplier=0,
        grad_w=grad_w,
        soft_grad_w=None,
    )
    site = generate_class_instance(Site, seed=seed, aggregator_id=aggregator_id)
    site.site_der_setting = der_setting
    return site


def _make_archive_doe(
    site_id: int,
    group_id: int,
    doe_id: int,
    start: datetime,
    duration_seconds: int,
    *,
    export_limit: Decimal | None = None,
    import_limit: Decimal | None = None,
    ramp_time_seconds: Decimal | None = None,
    superseded: bool = False,
    archive_time: datetime | None = None,
    deleted_time: datetime | None = None,
    seed: int = 1,
) -> ArchiveDynamicOperatingEnvelope:
    end = start + timedelta(seconds=duration_seconds)
    return generate_class_instance(
        ArchiveDynamicOperatingEnvelope,
        seed=seed,
        archive_id=None,
        dynamic_operating_envelope_id=doe_id,
        site_id=site_id,
        site_control_group_id=group_id,
        calculation_log_id=None,
        start_time=start,
        end_time=end,
        duration_seconds=duration_seconds,
        created_time=start - timedelta(seconds=30),
        changed_time=start - timedelta(seconds=30),
        export_limit_watts=export_limit,
        import_limit_active_watts=import_limit,
        generation_limit_active_watts=None,
        load_limit_active_watts=None,
        ramp_time_seconds=ramp_time_seconds,
        set_connected=None,
        set_energized=None,
        superseded=superseded,
        set_point_percentage=None,
        randomize_start_seconds=None,
        storage_target_active_watts=None,
        display_id=None,
        archive_time=archive_time,
        deleted_time=deleted_time,
    )


def _make_subscription(
    group_id: int | None,
    *,
    resource_type: SubscriptionResource = SubscriptionResource.DYNAMIC_OPERATING_ENVELOPE,
) -> Subscription:
    sub = Subscription()
    sub.aggregator_id = 1
    sub.changed_time = T0
    sub.resource_type = resource_type
    sub.resource_id = group_id
    sub.scoped_site_id = None
    sub.notification_uri = "https://example.com/notify"
    sub.entity_limit = 100
    return sub


# ─── _get_der_setting ─────────────────────────────────────────────────────────


async def test_get_der_setting_no_site(pg_envoy_base_config):
    """Returns None when no sites exist in the DB."""
    async with generate_async_session(pg_envoy_base_config) as session:
        result = await _get_der_setting(session)
    assert result is None


async def test_get_der_setting_no_der_setting(pg_envoy_base_config):
    """Returns None when a site exists but has no SiteDERSetting attached."""
    async with generate_async_session(pg_envoy_base_config) as session:
        site = generate_class_instance(Site, seed=1, aggregator_id=1)
        site.site_der_setting = None
        session.add(site)
        await session.commit()

    async with generate_async_session(pg_envoy_base_config) as session:
        result = await _get_der_setting(session)

    assert result is None


async def test_get_der_setting_returns_max_w_fields(pg_envoy_base_config):
    """Returns the correct max_w_value and max_w_multiplier from the active site's DER setting."""
    async with generate_async_session(pg_envoy_base_config) as session:
        site = _make_site_with_setting(aggregator_id=1, max_w=7500)
        session.add(site)
        await session.commit()

    async with generate_async_session(pg_envoy_base_config) as session:
        result = await _get_der_setting(session)

    assert result is not None
    assert result.max_w_value == 7500
    assert result.max_w_multiplier == 0


async def test_get_der_setting_uses_most_recently_changed_site(pg_envoy_base_config):
    """When multiple sites exist, returns the DER setting belonging to the site with the latest changed_time."""
    async with generate_async_session(pg_envoy_base_config) as session:
        old_site = _make_site_with_setting(aggregator_id=1, max_w=1000, seed=1)
        old_site.changed_time = T0 - timedelta(hours=2)
        session.add(old_site)
        await session.flush()

        new_site = _make_site_with_setting(aggregator_id=1, max_w=9000, seed=2)
        new_site.changed_time = T0 - timedelta(hours=1)
        session.add(new_site)
        await session.commit()

    async with generate_async_session(pg_envoy_base_config) as session:
        result = await _get_der_setting(session)

    assert result is not None
    assert result.max_w_value == 9000


# ─── _get_control_groups ──────────────────────────────────────────────────────


async def test_get_control_groups_empty(pg_envoy_base_config):
    """Returns an empty list when no SiteControlGroups exist."""
    async with generate_async_session(pg_envoy_base_config) as session:
        result = await _get_control_groups(session)
    assert result == []


async def test_get_control_groups_returns_all_with_correct_fields(pg_envoy_base_config):
    """Returns all groups with the correct site_control_group_id and primacy values."""
    async with generate_async_session(pg_envoy_base_config) as session:
        grp1 = generate_class_instance(SiteControlGroup, seed=1, site_control_group_id=1, primacy=10)
        grp2 = generate_class_instance(SiteControlGroup, seed=2, site_control_group_id=2, primacy=20)
        session.add_all([grp1, grp2])
        await session.commit()

    async with generate_async_session(pg_envoy_base_config) as session:
        result = await _get_control_groups(session)

    assert len(result) == 2
    by_id = {g.site_control_group_id: g for g in result}
    assert by_id[1].primacy == 10
    assert by_id[2].primacy == 20


# ─── _get_subscribed_group_ids ────────────────────────────────────────────────


async def test_get_subscribed_group_ids_empty(pg_envoy_base_config):
    """Returns an empty set when no subscriptions exist."""
    async with generate_async_session(pg_envoy_base_config) as session:
        result = await _get_subscribed_group_ids(session)
    assert result == set()


async def test_get_subscribed_group_ids_returns_doe_resource_ids(pg_envoy_base_config):
    """Returns the resource_ids for DOE subscriptions that have a non-null resource_id."""
    async with generate_async_session(pg_envoy_base_config) as session:
        session.add(_make_subscription(group_id=1))
        session.add(_make_subscription(group_id=2))
        await session.commit()

    async with generate_async_session(pg_envoy_base_config) as session:
        result = await _get_subscribed_group_ids(session)

    assert result == {1, 2}


async def test_get_subscribed_group_ids_excludes_null_resource_id(pg_envoy_base_config):
    """DOE subscriptions with resource_id=None (subscribe-all) are excluded."""
    async with generate_async_session(pg_envoy_base_config) as session:
        session.add(_make_subscription(group_id=5))
        session.add(_make_subscription(group_id=None))  # subscribe-all, no specific group
        await session.commit()

    async with generate_async_session(pg_envoy_base_config) as session:
        result = await _get_subscribed_group_ids(session)

    assert result == {5}


async def test_get_subscribed_group_ids_excludes_non_doe_subscriptions(
    pg_envoy_base_config,
):
    """Non-DOE subscription types are not included even when they have a resource_id."""
    async with generate_async_session(pg_envoy_base_config) as session:
        session.add(_make_subscription(group_id=7))
        session.add(_make_subscription(group_id=99, resource_type=SubscriptionResource.SITE))
        await session.commit()

    async with generate_async_session(pg_envoy_base_config) as session:
        result = await _get_subscribed_group_ids(session)

    assert result == {7}


# ─── _get_does ────────────────────────────────────────────────────────────────


async def test_get_does_empty(pg_envoy_base_config):
    """Returns an empty list when no DOEs exist."""
    async with generate_async_session(pg_envoy_base_config) as session:
        has_storage_target = await _check_has_storage_target(session)
        result = await _get_does(session, has_storage_target=has_storage_target)
    assert result == []


@pytest.mark.parametrize("seed, optional_is_none", product([101, 202], [True, False]))
async def test_get_does_active_doe_fields(pg_envoy_base_config, seed: int, optional_is_none: bool):
    """Active DOE rows are returned with is_archive=False and correct field values."""

    async with generate_async_session(pg_envoy_base_config) as session:
        site = _make_site_with_setting(aggregator_id=1)
        session.add(site)
        grp = generate_class_instance(SiteControlGroup, seed=1, site_control_group_id=1, primacy=1)
        session.add(grp)
        doe = generate_class_instance(
            DynamicOperatingEnvelope,
            seed=seed,
            optional_is_none=optional_is_none,
            site=site,
            site_control_group=grp,
            calculation_log_id=None,
        )
        session.add(doe)
        await session.flush()

        original_doe = clone_class_instance(doe)
        await session.commit()

    async with generate_async_session(pg_envoy_base_config) as session:
        has_storage_target = await _check_has_storage_target(session)
        result = await _get_does(session, has_storage_target=has_storage_target)

    assert len(result) == 1
    row = result[0]
    ignored: set[str] = {"is_archive", "deleted_time", "archive_time"}
    if not has_storage_target:
        ignored.add("storage_target_active_watts")
    assert_class_instance_equality(_RawDOE, original_doe, row, ignored_properties=ignored)
    assert row.is_archive is False
    assert row.deleted_time is None
    assert row.archive_time is None


@pytest.mark.parametrize("seed, optional_is_none", product([101, 202], [True, False]))
async def test_get_does_archive_doe_fields(pg_envoy_base_config, seed: int, optional_is_none: bool):
    """Archive DOE rows are returned with is_archive=True and correct field values."""

    async with generate_async_session(pg_envoy_base_config) as session:
        site = _make_site_with_setting(aggregator_id=1)
        session.add(site)
        grp = generate_class_instance(SiteControlGroup, seed=1, site_control_group_id=1, primacy=1)
        session.add(grp)
        archive_doe = generate_class_instance(
            ArchiveDynamicOperatingEnvelope,
            seed=seed,
            optional_is_none=optional_is_none,
            calculation_log_id=None,
            site_id=site.site_id,
            site_control_group_id=grp.site_control_group_id,
        )
        session.add(archive_doe)
        await session.flush()

        original__archive_doe = clone_class_instance(archive_doe)
        await session.commit()

    async with generate_async_session(pg_envoy_base_config) as session:
        has_storage_target = await _check_has_storage_target(session)
        result = await _get_does(session, has_storage_target=has_storage_target)

    assert len(result) == 1
    row = result[0]
    ignored: set[str] = {"is_archive"}
    if not has_storage_target:
        ignored.add("storage_target_active_watts")
    assert_class_instance_equality(_RawDOE, original__archive_doe, row, ignored_properties=ignored)
    assert row.is_archive is True


async def test_get_does_combines_active_and_archive(pg_envoy_base_config):
    """Both active and archive DOEs are returned together; is_archive distinguishes them."""
    doe_start = T0 + timedelta(minutes=5)
    duration = 300

    async with generate_async_session(pg_envoy_base_config) as session:
        site = _make_site_with_setting(aggregator_id=1)
        session.add(site)
        grp = generate_class_instance(SiteControlGroup, seed=1, site_control_group_id=1, primacy=1)
        session.add(grp)
        active_doe = generate_class_instance(
            DynamicOperatingEnvelope,
            seed=2,
            site=site,
            site_control_group=grp,
            calculation_log_id=None,
            start_time=doe_start,
            end_time=doe_start + timedelta(seconds=duration),
            duration_seconds=duration,
            created_time=doe_start - timedelta(seconds=30),
            changed_time=doe_start - timedelta(seconds=30),
            export_limit_watts=Decimal("2000"),
            import_limit_active_watts=None,
            generation_limit_active_watts=None,
            load_limit_active_watts=None,
            ramp_time_seconds=None,
            set_connected=None,
            superseded=False,
            set_energized=None,
            set_point_percentage=None,
            randomize_start_seconds=None,
        )
        session.add(active_doe)
        await session.flush()
        site_id = site.site_id

        archive_doe = _make_archive_doe(
            site_id=site_id,
            group_id=1,
            doe_id=999,
            start=doe_start + timedelta(minutes=10),
            duration_seconds=300,
            export_limit=Decimal("8000"),
            archive_time=doe_start + timedelta(minutes=15),
            seed=3,
        )
        session.add(archive_doe)
        await session.commit()

    async with generate_async_session(pg_envoy_base_config) as session:
        has_storage_target = await _check_has_storage_target(session)
        result = await _get_does(session, has_storage_target=has_storage_target)

    assert len(result) == 2
    archive_flags = {row.dynamic_operating_envelope_id: row.is_archive for row in result}
    active_id = next(r.dynamic_operating_envelope_id for r in result if not r.is_archive)
    assert archive_flags[active_id] is False
    assert archive_flags[999] is True


async def test_get_does_scoped_to_active_site(pg_envoy_base_config):
    """Only DOEs belonging to the most-recently-changed site are returned."""

    async with generate_async_session(pg_envoy_base_config) as session:
        # Older site — its DOEs should NOT be returned
        old_site = _make_site_with_setting(aggregator_id=1, seed=1)
        old_site.changed_time = T0 - timedelta(hours=2)
        session.add(old_site)

        # Newer site — the "active" site whose DOEs should be returned
        new_site = _make_site_with_setting(aggregator_id=1, seed=2)
        new_site.changed_time = T0 - timedelta(hours=1)
        session.add(new_site)

        grp = generate_class_instance(SiteControlGroup, seed=1, site_control_group_id=1, primacy=1)
        session.add(grp)
        await session.flush()

        old_doe = generate_class_instance(
            DynamicOperatingEnvelope,
            seed=11,
            site=old_site,
            site_control_group=grp,
            calculation_log_id=None,
            export_limit_watts=Decimal("1111"),
        )
        new_doe = generate_class_instance(
            DynamicOperatingEnvelope,
            seed=22,
            site=new_site,
            site_control_group=grp,
            calculation_log_id=None,
            export_limit_watts=Decimal("9999"),
        )
        session.add_all([old_doe, new_doe])
        await session.commit()

    async with generate_async_session(pg_envoy_base_config) as session:
        has_storage_target = await _check_has_storage_target(session)
        result = await _get_does(session, has_storage_target=has_storage_target)

    assert len(result) == 1
    assert result[0].export_limit_watts == pytest.approx(9999.0)


# ─── _get_defaults ────────────────────────────────────────────────────────────


async def test_get_defaults_empty(pg_envoy_base_config):
    """Returns an empty list when no SiteControlGroupDefaults exist."""
    async with generate_async_session(pg_envoy_base_config) as session:
        has_storage_target = await _check_has_storage_target(session)
        result = await _get_defaults(session, has_storage_target=has_storage_target)
    assert result == []


@pytest.mark.parametrize("seed, optional_is_none", product([101, 202], [True, False]))
async def test_get_defaults_active_default_fields(pg_envoy_base_config, seed: int, optional_is_none: bool):
    """Active default rows are returned with is_archive=False and correct field values."""

    async with generate_async_session(pg_envoy_base_config) as session:
        grp = generate_class_instance(SiteControlGroup, seed=1, site_control_group_id=3, primacy=1)
        session.add(grp)
        default = generate_class_instance(
            SiteControlGroupDefault,
            seed=seed,
            optional_is_none=optional_is_none,
            site_control_group=grp,
        )
        session.add(default)

        original_default = clone_class_instance(default)
        await session.commit()

    async with generate_async_session(pg_envoy_base_config) as session:
        has_storage_target = await _check_has_storage_target(session)
        result = await _get_defaults(session, has_storage_target=has_storage_target)

    assert len(result) == 1
    row = result[0]

    ignored: set[str] = {"is_archive", "archive_time", "deleted_time"}
    if not has_storage_target:
        ignored.add("storage_target_active_watts")
    assert_class_instance_equality(_RawDefault, original_default, row, ignored_properties=ignored)
    assert row.is_archive is False
    assert row.archive_time is None
    assert row.deleted_time is None


@pytest.mark.parametrize("seed, optional_is_none", product([101, 202], [True, False]))
async def test_get_defaults_archive_default_fields(pg_envoy_base_config, seed: int, optional_is_none: bool):
    """Archive default rows are returned with is_archive=True and archive_time populated."""

    archive_time = datetime(2022, 11, 14, tzinfo=UTC)
    async with generate_async_session(pg_envoy_base_config) as session:
        archive_default = generate_class_instance(
            ArchiveSiteControlGroupDefault,
            seed=seed,
            optional_is_none=optional_is_none,
            archive_time=archive_time,
        )
        session.add(archive_default)

        original_archive_default = clone_class_instance(archive_default)

        await session.commit()

    async with generate_async_session(pg_envoy_base_config) as session:
        has_storage_target = await _check_has_storage_target(session)
        result = await _get_defaults(session, has_storage_target=has_storage_target)

    assert len(result) == 1
    row = result[0]
    ignored: set[str] = {"is_archive"}
    if not has_storage_target:
        ignored.add("storage_target_active_watts")
    assert_class_instance_equality(_RawDefault, original_archive_default, row, ignored_properties=ignored)
    assert row.is_archive is True


async def test_get_defaults_combines_active_and_archive(pg_envoy_base_config):
    """Both active and archive defaults are returned together; is_archive distinguishes them."""

    async with generate_async_session(pg_envoy_base_config) as session:
        grp = generate_class_instance(SiteControlGroup, seed=1, site_control_group_id=1, primacy=1)
        session.add(grp)
        active_default = generate_class_instance(
            SiteControlGroupDefault,
            seed=1,
            site_control_group=grp,
            export_limit_active_watts=Decimal("5000"),
        )
        session.add(active_default)

        archive_default = generate_class_instance(
            ArchiveSiteControlGroupDefault,
            seed=2,
            site_control_group_id=2,
            export_limit_active_watts=Decimal("7000"),
        )
        session.add(archive_default)
        await session.commit()

    async with generate_async_session(pg_envoy_base_config) as session:
        has_storage_target = await _check_has_storage_target(session)
        result = await _get_defaults(session, has_storage_target=has_storage_target)

    assert len(result) == 2
    by_group = {r.site_control_group_id: r for r in result}
    assert by_group[1].is_archive is False
    assert by_group[1].export_limit_active_watts == pytest.approx(5000.0)
    assert by_group[2].is_archive is True
    assert by_group[2].export_limit_active_watts == pytest.approx(7000.0)


async def test_get_defaults_not_scoped_to_site(pg_envoy_base_config):
    """Defaults are returned regardless of which site is active (no site scoping)."""
    async with generate_async_session(pg_envoy_base_config) as session:
        # No site in the DB — yet defaults should still be returned
        archive_default = generate_class_instance(
            ArchiveSiteControlGroupDefault,
            site_control_group_id=42,
            export_limit_active_watts=Decimal("1234"),
        )
        session.add(archive_default)
        await session.commit()

    async with generate_async_session(pg_envoy_base_config) as session:
        has_storage_target = await _check_has_storage_target(session)
        result = await _get_defaults(session, has_storage_target=has_storage_target)

    assert len(result) == 1
    assert result[0].site_control_group_id == 42


# ─── storage_target_active_watts (v1.3 column, simulated on v1.2 schema) ──────


async def test_check_has_storage_target_on_schema(pg_envoy_base_config):
    """We're agnostic of the underlying envoy version - we're a bit limited in how we can run this test"""
    async with generate_async_session(pg_envoy_base_config) as session:
        result = await _check_has_storage_target(session)
        assert isinstance(result, bool)


async def test_get_does_storage_target_none_when_column_absent(pg_envoy_base_config):
    """When has_storage_target=False, storage_target_active_watts is None for every row."""
    async with generate_async_session(pg_envoy_base_config) as session:
        site = _make_site_with_setting(aggregator_id=1)
        session.add(site)
        grp = generate_class_instance(SiteControlGroup, seed=1, site_control_group_id=1, primacy=1)
        session.add(grp)
        doe = _make_doe(site, grp, offset_minutes=5, duration_minutes=10, export_limit=Decimal("8000"), seed=1)
        session.add(doe)
        await session.commit()

    async with generate_async_session(pg_envoy_base_config) as session:
        result = await _get_does(session, has_storage_target=False)

    assert len(result) == 1
    assert result[0].storage_target_active_watts is None


async def test_get_does_reads_storage_target_when_column_present(pg_envoy_base_config):
    """_check_has_storage_target returns True and _get_does reads storage_target_active_watts when the column exists."""
    async with generate_async_session(pg_envoy_base_config) as session:
        await session.execute(
            text(
                "ALTER TABLE dynamic_operating_envelope "
                "ADD COLUMN IF NOT EXISTS storage_target_active_watts DECIMAL(16,2)"
            )
        )
        await session.execute(
            text(
                "ALTER TABLE archive_dynamic_operating_envelope "
                "ADD COLUMN IF NOT EXISTS storage_target_active_watts DECIMAL(16,2)"
            )
        )
        site = _make_site_with_setting(aggregator_id=1)
        session.add(site)
        grp = generate_class_instance(SiteControlGroup, seed=1, site_control_group_id=1, primacy=1)
        session.add(grp)
        doe = _make_doe(
            site,
            grp,
            offset_minutes=5,
            duration_minutes=10,
            export_limit=Decimal("8000"),
            seed=1,
        )
        session.add(doe)
        await session.flush()
        doe_id = doe.dynamic_operating_envelope_id
        await session.execute(
            text(
                "UPDATE dynamic_operating_envelope "
                "SET storage_target_active_watts = :val "
                "WHERE dynamic_operating_envelope_id = :id"
            ),
            {"val": 3000, "id": doe_id},
        )
        await session.commit()

    async with generate_async_session(pg_envoy_base_config) as session:
        assert await _check_has_storage_target(session) is True
        result = await _get_does(session, has_storage_target=True)

    assert len(result) == 1
    assert result[0].storage_target_active_watts == pytest.approx(3000.0)
    assert result[0].export_limit_watts == pytest.approx(8000.0)


async def test_chart_storage_target_constrains_upper_and_lower_bounds(
    pg_envoy_base_config,
):
    """
    Simulates v1.3 schema by adding storage_target_active_watts via raw SQL.

    Two DOEs exercise both sign conventions:
      - T+5m:  storage_target=+4000W, export_limit=9000W → storage target binds (upper = 4000W)
      - T+20m: storage_target=−2500W, no import limit   → storage target is the only lower bound (2500W)

    Expected visual:
      - Upper trace: steps to 4000W at T+5m
      - Lower trace: steps to −2500W at T+20m
    """
    test_end = T0 + timedelta(minutes=40)

    async with generate_async_session(pg_envoy_base_config) as session:
        for tbl in [
            "dynamic_operating_envelope",
            "archive_dynamic_operating_envelope",
            "site_control_group_default",
            "archive_site_control_group_default",
        ]:
            await session.execute(
                text(f"ALTER TABLE {tbl} ADD COLUMN IF NOT EXISTS storage_target_active_watts DECIMAL(16,2)")
            )

        site = _make_site_with_setting(aggregator_id=1)
        session.add(site)
        grp = generate_class_instance(SiteControlGroup, seed=1, site_control_group_id=1, primacy=1)
        session.add(grp)

        doe_upper = _make_doe(
            site,
            grp,
            offset_minutes=5,
            duration_minutes=10,
            export_limit=Decimal("9000"),
            seed=10,
        )
        doe_lower = _make_doe(site, grp, offset_minutes=20, duration_minutes=10, seed=20)
        session.add_all([doe_upper, doe_lower])
        await session.flush()
        created_upper = doe_upper.created_time
        created_lower = doe_lower.created_time

        await session.execute(
            text(
                "UPDATE dynamic_operating_envelope "
                "SET storage_target_active_watts = :val "
                "WHERE dynamic_operating_envelope_id = :id"
            ),
            {"val": 4000, "id": doe_upper.dynamic_operating_envelope_id},
        )
        await session.execute(
            text(
                "UPDATE dynamic_operating_envelope "
                "SET storage_target_active_watts = :val "
                "WHERE dynamic_operating_envelope_id = :id"
            ),
            {"val": -2500, "id": doe_lower.dynamic_operating_envelope_id},
        )
        await session.commit()

    polls = [
        _poll(1, created_upper + timedelta(seconds=30), req_id=1),
        _poll(1, created_lower + timedelta(seconds=30), req_id=2),
    ]

    async with generate_async_session(pg_envoy_base_config) as session:
        html = await generate_power_limit_chart_html(session, T0, test_end, polls)

    assert html is not None, "Chart generation returned None"
    assert "Device Power Chart" in html
    # storage_target=+4000 should bind the upper trace (export) at 4000W
    assert "4000" in html
    # storage_target=-2500 should bind the lower trace (import) at -2500W
    assert "-2500" in html
    out = _out("scenario_storage_target_v13.html")
    out.write_text(html)
    print(f"\n  ✓ Storage target scenario → {out}")


# ─── Unit tests: _get_effective_upper_at / _get_effective_lower_at ────────────


def _u_doe(
    *,
    export_limit: float | None = None,
    gen_limit: float | None = None,
    import_limit: float | None = None,
    load_limit: float | None = None,
    storage_target: float | None = None,
    site_control_group_id: int = 1,
) -> _RawDOE:
    return _RawDOE(
        dynamic_operating_envelope_id=1,
        site_control_group_id=site_control_group_id,
        created_time=T0,
        start_time=T0,
        duration_seconds=3600,
        superseded=False,
        export_limit_watts=export_limit,
        generation_limit_active_watts=gen_limit,
        import_limit_active_watts=import_limit,
        load_limit_active_watts=load_limit,
        set_connected=None,
        set_energized=None,
        ramp_time_seconds=None,
        storage_target_active_watts=storage_target,
        is_archive=False,
        deleted_time=None,
        archive_time=None,
    )


def _u_ctrl(doe: _RawDOE) -> _KnownControlSegment:
    return _KnownControlSegment(
        row=doe,
        site_control_group_id=doe.site_control_group_id,
        primacy=1,
        observed_at=T0,
        effective_start=T0,
        effective_end=T0 + timedelta(hours=2),
        step_name="",
    )


def _u_default(
    *,
    export_limit: float | None = None,
    gen_limit: float | None = None,
    import_limit: float | None = None,
    load_limit: float | None = None,
    storage_target: float | None = None,
    site_control_group_id: int = 1,
) -> _RawDefault:
    return _RawDefault(
        site_control_group_id=site_control_group_id,
        changed_time=T0,
        export_limit_active_watts=export_limit,
        generation_limit_active_watts=gen_limit,
        import_limit_active_watts=import_limit,
        load_limit_active_watts=load_limit,
        ramp_rate_percent_per_second=None,
        storage_target_active_watts=storage_target,
        is_archive=False,
        deleted_time=None,
        archive_time=None,
    )


def _u_group(site_control_group_id: int = 1, primacy: int = 1) -> _RawControlGroup:
    return _RawControlGroup(site_control_group_id=site_control_group_id, primacy=primacy)


def _u_known_defaults(default: _RawDefault) -> dict[int, list[_Known[_RawDefault]]]:
    """Wrap a raw default as known to the client for all time."""
    return {
        default.site_control_group_id: [
            _Known(row=default, known_from=T0 - timedelta(hours=1), known_until=_FAR_FUTURE)
        ]
    }


@pytest.mark.parametrize(
    "export_limit, gen_limit, storage_target, expected_watts",
    [
        (9000.0, None, 4000.0, 4000.0),  # storage binds over export
        (4000.0, None, 9000.0, 4000.0),  # export binds over storage
        (None, None, 4000.0, 4000.0),  # storage is the only upper bound
        (5000.0, None, None, 5000.0),  # only export (baseline, no storage)
        (5000.0, 3000.0, None, 3000.0),  # gen more restrictive than export (baseline)
        (None, None, None, None),  # unconstrained
        (5000.0, None, -3000.0, 5000.0),  # negative storage never constrains upper
        (5000.0, None, 0.0, 5000.0),  # zero storage never constrains upper
        (9000.0, 8000.0, 3000.0, 3000.0),  # all three present; storage binds
        (9000.0, 4000.0, 5000.0, 4000.0),  # all three present; gen binds
    ],
)
def test_get_effective_upper_at_with_active_control(
    export_limit: float | None,
    gen_limit: float | None,
    storage_target: float | None,
    expected_watts: float | None,
):
    t = T0 + timedelta(minutes=30)
    doe = _u_doe(export_limit=export_limit, gen_limit=gen_limit, storage_target=storage_target)
    ctrl = _u_ctrl(doe)
    group = _u_group()
    val, src = _get_effective_upper_at(t, [group], {ctrl.site_control_group_id: [ctrl]}, {})
    if expected_watts is None:
        assert val is None
        assert src is None
    else:
        assert val == pytest.approx(expected_watts)
        assert src is ctrl


@pytest.mark.parametrize(
    "import_limit, load_limit, storage_target, expected_watts",
    [
        (None, None, -2500.0, 2500.0),  # storage is the only lower bound
        (1000.0, None, -2500.0, 1000.0),  # import binds (1000 < 2500)
        (5000.0, None, -2500.0, 2500.0),  # storage binds (2500 < 5000)
        (5000.0, None, None, 5000.0),  # only import (baseline, no storage)
        (5000.0, 3000.0, None, 3000.0),  # load more restrictive than import (baseline)
        (None, None, None, None),  # unconstrained
        (None, None, 4000.0, None),  # positive storage never constrains lower
        (None, None, 0.0, None),  # zero storage never constrains lower
        (9000.0, 8000.0, -3000.0, 3000.0),  # all three present; storage binds
    ],
)
def test_get_effective_lower_at_with_active_control(
    import_limit: float | None,
    load_limit: float | None,
    storage_target: float | None,
    expected_watts: float | None,
):
    t = T0 + timedelta(minutes=30)
    doe = _u_doe(import_limit=import_limit, load_limit=load_limit, storage_target=storage_target)
    ctrl = _u_ctrl(doe)
    group = _u_group()
    val, src = _get_effective_lower_at(t, [group], {ctrl.site_control_group_id: [ctrl]}, {})
    if expected_watts is None:
        assert val is None
        assert src is None
    else:
        assert val == pytest.approx(expected_watts)
        assert src is ctrl


def test_get_effective_upper_at_storage_target_from_default():
    """Falls back to default when no active control; positive storage target sets upper bound."""
    t = T0 + timedelta(minutes=30)
    default = _u_default(storage_target=4000.0)
    group = _u_group()
    val, src = _get_effective_upper_at(t, [group], {}, _u_known_defaults(default))
    assert val == pytest.approx(4000.0)
    assert isinstance(src, _Known) and src.row is default


def test_get_effective_lower_at_storage_target_from_default():
    """Falls back to default when no active control; negative storage target sets lower bound."""
    t = T0 + timedelta(minutes=30)
    default = _u_default(storage_target=-2000.0)
    group = _u_group()
    val, src = _get_effective_lower_at(t, [group], {}, _u_known_defaults(default))
    assert val == pytest.approx(2000.0)
    assert isinstance(src, _Known) and src.row is default


# ─── Scenario A: Single program, export curtailment steps with AS4777 ramps ──


async def test_chart_single_program_export_curtailment(pg_envoy_base_config):
    """
    One DERProgram (primacy 1). Export is stepped down and back up over 40 minutes.
    Device polls 60 seconds after each control is created. AS4777 ramp rate (grad_w=28).

    Expected visual:
      - Upper trace starts at setMaxW (10000W)
      - Ramps down to 5000W at T+5m (visible ramp over ~3 min at AS4777 rate)
      - Ramps down to 0W at T+15m
      - Ramps back up to 10000W at T+25m
      - Lower trace flat at -10000W (no import limit set)
    """
    test_end = T0 + timedelta(minutes=45)

    created_times: list[datetime] = []

    async with generate_async_session(pg_envoy_base_config) as session:
        site = _make_site_with_setting(aggregator_id=1)
        session.add(site)
        group = generate_class_instance(SiteControlGroup, seed=1, site_control_group_id=1, primacy=1)
        session.add(group)

        ctrls = [
            _make_doe(
                site,
                group,
                offset_minutes=5,
                duration_minutes=10,
                export_limit=Decimal("5000"),
                seed=10,
            ),
            _make_doe(
                site,
                group,
                offset_minutes=15,
                duration_minutes=10,
                export_limit=Decimal("0"),
                seed=20,
            ),
            _make_doe(
                site,
                group,
                offset_minutes=25,
                duration_minutes=15,
                export_limit=Decimal("10000"),
                seed=30,
            ),
        ]
        session.add_all(ctrls)
        await session.flush()  # Assign IDs without closing session
        created_times = [c.created_time for c in ctrls]  # Read while session still open
        await session.commit()

    polls = [_poll(1, t + timedelta(seconds=60), req_id=i) for i, t in enumerate(created_times)]

    async with generate_async_session(pg_envoy_base_config) as session:
        html = await generate_power_limit_chart_html(session, T0, test_end, polls)

    assert html is not None, "Chart generation returned None"
    assert "Device Power Chart" in html
    out = _out("scenario_A_single_program_export0.html")
    out.write_text(html)
    print(f"\n  ✓ Scenario A → {out}")


# ─── Scenario B: Two programs, primacy resolution, import + export limits ─────


async def test_chart_multi_program_primacy(pg_envoy_base_config):
    """
    Two DERPrograms operating simultaneously on different limit types:
      - Program 1 (primacy 1): sets IMPORT limits (lower trace)
      - Program 2 (primacy 2): sets EXPORT limits (upper trace)

    Expected visual:
      - Upper trace driven by Program 2 controls, stepped and ramped
      - Lower trace driven by Program 1 controls, independently ramped
    """
    test_end = T0 + timedelta(minutes=50)
    created_times: dict[str, datetime] = {}

    async with generate_async_session(pg_envoy_base_config) as session:
        site = _make_site_with_setting(aggregator_id=1)
        session.add(site)
        grp1 = generate_class_instance(SiteControlGroup, seed=1, site_control_group_id=1, primacy=1)
        grp2 = generate_class_instance(SiteControlGroup, seed=2, site_control_group_id=2, primacy=2)
        session.add_all([grp1, grp2])

        ctrls = {
            "imp1": _make_doe(
                site,
                grp1,
                offset_minutes=5,
                duration_minutes=15,
                import_limit=Decimal("0"),
                seed=11,
            ),
            "imp2": _make_doe(
                site,
                grp1,
                offset_minutes=20,
                duration_minutes=15,
                import_limit=Decimal("3000"),
                seed=12,
            ),
            "exp1": _make_doe(
                site,
                grp2,
                offset_minutes=10,
                duration_minutes=10,
                export_limit=Decimal("4000"),
                seed=21,
            ),
            "exp2": _make_doe(
                site,
                grp2,
                offset_minutes=30,
                duration_minutes=15,
                export_limit=Decimal("2000"),
                seed=22,
            ),
        }
        session.add_all(ctrls.values())
        await session.flush()
        created_times = {k: v.created_time for k, v in ctrls.items()}
        await session.commit()

    polls = [
        _poll(1, created_times["imp1"] + timedelta(seconds=90), req_id=1),
        _poll(1, created_times["imp2"] + timedelta(seconds=90), req_id=2),
        _poll(2, created_times["exp1"] + timedelta(seconds=90), req_id=3),
        _poll(2, created_times["exp2"] + timedelta(seconds=90), req_id=4),
    ]

    async with generate_async_session(pg_envoy_base_config) as session:
        html = await generate_power_limit_chart_html(session, T0, test_end, polls)

    assert html is not None
    assert "Device Power Chart" in html
    out = _out("scenario_B_multi_program_primacy0.html")
    out.write_text(html)
    print(f"\n  ✓ Scenario B → {out}")


# ─── Scenario C: rampTms on controls, default control as baseline ─────────────


async def test_chart_ramptms_and_defaults(pg_envoy_base_config):
    """
    Demonstrates rampTms (explicit 120s ramp) and a default control baseline.

    Program 1 (primacy 1):
      - Default export=8000W active from test start
      - T+5m: export=1000W with rampTms=120s → visible 2-minute ramp
      - T+15m: control expires → ramps back to default 8000W via grad_w rate
      - T+25m: export=0W with no rampTms → falls to grad_w (AS4777) rate

    Expected visual:
      - Upper trace starts at 8000W (default)
      - 2-minute sloped ramp to 1000W at T+5m
      - grad_w ramp back to 8000W at T+15m
      - grad_w ramp down to 0W at T+25m
    """
    test_end = T0 + timedelta(minutes=40)
    created_times: dict[str, datetime] = {}

    async with generate_async_session(pg_envoy_base_config) as session:
        site = _make_site_with_setting(aggregator_id=1)
        session.add(site)
        grp1 = generate_class_instance(SiteControlGroup, seed=1, site_control_group_id=1, primacy=1)
        session.add(grp1)

        session.add(
            generate_class_instance(
                SiteControlGroupDefault,
                seed=1,
                site_control_group=grp1,
                import_limit_active_watts=None,
                export_limit_active_watts=Decimal("8000"),
                generation_limit_active_watts=None,
                load_limit_active_watts=None,
                ramp_rate_percent_per_second=None,
                storage_target_active_watts=None,
                changed_time=T0 - timedelta(minutes=1),
            )
        )

        ctrls = {
            "ctrl1": _make_doe(
                site,
                grp1,
                offset_minutes=5,
                duration_minutes=10,
                export_limit=Decimal("1000"),
                ramp_time_seconds=Decimal("120"),
                seed=10,
            ),
            "ctrl2": _make_doe(
                site,
                grp1,
                offset_minutes=25,
                duration_minutes=10,
                export_limit=Decimal("0"),
                seed=20,
            ),
        }
        session.add_all(ctrls.values())
        await session.flush()
        created_times = {k: v.created_time for k, v in ctrls.items()}
        await session.commit()

    # Near-instant polls (simulating subscription-speed receipt)
    polls = [
        _dderc_poll(1, T0 + timedelta(seconds=5), req_id=0),
        _poll(1, created_times["ctrl1"] + timedelta(seconds=1), req_id=1),
        _poll(1, created_times["ctrl2"] + timedelta(seconds=1), req_id=2),
    ]

    async with generate_async_session(pg_envoy_base_config) as session:
        html = await generate_power_limit_chart_html(session, T0, test_end, polls)

    assert html is not None
    assert "Device Power Chart" in html
    out = _out("scenario_C_ramptms_and_defaults0.html")
    out.write_text(html)
    print(f"\n  ✓ Scenario C → {out}")


# ─── Scenario D: opModConnect disconnect and reconnect grace period ───────────


async def test_chart_op_mod_connect(pg_envoy_base_config):
    """
    Demonstrates opModConnect=False disconnect (power=0) and 1-minute grace after explicit
    True-control reconnect.

    Program 1:
      - Default export=7000W
      - T+5m: export control 5000W begins (spanning full test)
      - T+10m: opModConnect=False (duration 5min, expires T+15m) → power forced to 0
      - T+15m: False control expires → reconnect triggered, 1-min grace (power still 0)
      - T+16m: grace ends → resumes 5000W export control
      - T+20m: opModConnect=True (already reconnected, no effect here)

    Expected visual:
      - Upper trace: 5000W from T+5m, drops to 0 at T+10m, ramps back to 5000W at T+16m
      - Lower trace: flat at -10000W (no import limit set)
    """
    test_end = T0 + timedelta(minutes=35)
    created_times: dict[str, datetime] = {}

    async with generate_async_session(pg_envoy_base_config) as session:
        site = _make_site_with_setting(aggregator_id=1)
        session.add(site)
        grp1 = generate_class_instance(SiteControlGroup, seed=1, site_control_group_id=1, primacy=1)
        session.add(grp1)

        session.add(
            generate_class_instance(
                SiteControlGroupDefault,
                seed=1,
                site_control_group=grp1,
                import_limit_active_watts=None,
                export_limit_active_watts=Decimal("7000"),
                generation_limit_active_watts=None,
                load_limit_active_watts=None,
                ramp_rate_percent_per_second=None,
                storage_target_active_watts=None,
                changed_time=T0 - timedelta(minutes=1),
            )
        )

        ctrls = {
            "export": _make_doe(
                site,
                grp1,
                offset_minutes=5,
                duration_minutes=25,
                export_limit=Decimal("5000"),
                seed=10,
            ),
            "disconnect": _make_doe(
                site,
                grp1,
                offset_minutes=10,
                duration_minutes=5,
                set_connected=False,
                seed=20,
            ),
            "reconnect": _make_doe(
                site,
                grp1,
                offset_minutes=20,
                duration_minutes=5,
                set_connected=True,
                seed=30,
            ),
        }
        session.add_all(ctrls.values())
        await session.flush()
        created_times = {k: v.created_time for k, v in ctrls.items()}
        await session.commit()

    polls = [
        _dderc_poll(1, T0 + timedelta(seconds=5), req_id=0),
        _poll(1, created_times["export"] + timedelta(seconds=60), req_id=1),
        _poll(1, created_times["disconnect"] + timedelta(seconds=60), req_id=2),
        _poll(1, created_times["reconnect"] + timedelta(seconds=60), req_id=3),
    ]

    async with generate_async_session(pg_envoy_base_config) as session:
        html = await generate_power_limit_chart_html(session, T0, test_end, polls)

    assert html is not None
    assert "Device Power Chart" in html
    out = _out("scenario_D_op_mod_connect0.html")
    out.write_text(html)
    print(f"\n  ✓ Scenario D → {out}")


# ─── Scenario D2: opModConnect — expiry-triggered reconnect, no True control ──


async def test_chart_op_mod_connect_expiry(pg_envoy_base_config):
    """
    opModConnect=False control expires with no subsequent True control.
    Reconnection is triggered purely by expiry.

    Program 1:
      - Default export=7000W
      - T+5m: export control 5000W begins (spanning full test)
      - T+10m: opModConnect=False (duration 5min, expires T+15m) → power forced to 0
      - T+15m: False control expires → reconnect triggered, 1-min grace (power still 0)
      - T+16m: grace ends → resumes 5000W export control

    Expected visual:
      - Upper trace: 5000W from T+5m, drops to 0 at T+10m, ramps back to 5000W at T+16m
      - No True control — reconnect is entirely expiry-driven
    """
    test_end = T0 + timedelta(minutes=35)
    created_times: dict[str, datetime] = {}

    async with generate_async_session(pg_envoy_base_config) as session:
        site = _make_site_with_setting(aggregator_id=1)
        session.add(site)
        grp1 = generate_class_instance(SiteControlGroup, seed=1, site_control_group_id=1, primacy=1)
        session.add(grp1)

        session.add(
            generate_class_instance(
                SiteControlGroupDefault,
                seed=1,
                site_control_group=grp1,
                import_limit_active_watts=None,
                export_limit_active_watts=Decimal("7000"),
                generation_limit_active_watts=None,
                load_limit_active_watts=None,
                ramp_rate_percent_per_second=None,
                storage_target_active_watts=None,
                changed_time=T0 - timedelta(minutes=1),
            )
        )

        ctrls = {
            "export": _make_doe(
                site,
                grp1,
                offset_minutes=5,
                duration_minutes=25,
                export_limit=Decimal("5000"),
                seed=10,
            ),
            "disconnect": _make_doe(
                site,
                grp1,
                offset_minutes=10,
                duration_minutes=5,
                set_connected=False,
                seed=20,
            ),
        }
        session.add_all(ctrls.values())
        await session.flush()
        created_times = {k: v.created_time for k, v in ctrls.items()}
        await session.commit()

    polls = [
        _dderc_poll(1, T0 + timedelta(seconds=5), req_id=0),
        _poll(1, created_times["export"] + timedelta(seconds=60), req_id=1),
        _poll(1, created_times["disconnect"] + timedelta(seconds=60), req_id=2),
    ]

    async with generate_async_session(pg_envoy_base_config) as session:
        html = await generate_power_limit_chart_html(session, T0, test_end, polls)

    assert html is not None
    assert "Device Power Chart" in html
    out = _out("scenario_D2_op_mod_connect_expiry0.html")
    out.write_text(html)
    print(f"\n  ✓ Scenario D2 → {out}")


# ─── Scenario E: GEN-10 DERC4/5/6 — opModConnect + primacy + supersede ────────


async def test_chart_gen10_derc456(pg_envoy_base_config):
    """
    Approximates the GEN-10 DERC4/5/6 phase (primacy validation for generators).

    Two groups mirror GEN-10's FSA1 (primacy 1) and FSA2 (primacy 2):

      DERC4 — group 1, primacy 1, T+1m to T+5m:
        opModConnect=False + genLim=0.  Device is disconnected (power→0) from its
        receipt at T+1m until 1-min after expiry at T+6m.

      DERC5 — group 2, primacy 2, T+1m to T+8m:
        opModExpLimW=200% (20000 W — shown above setMaxW reference line).
        Effective once DERC4 grace ends at T+6m; group 1 has no export default
        so group 2's control wins.

      DERC6 — group 2, primacy 2, T+8m to T+13m:
        opModExpLimW=50% (5000 W).  Received at T+9m (non-overlapping with DERC5,
        no supersede record needed).  Upper trace ramps from 20000→10000→5000 W.

    Device is polled (no subscriptions). grad_w=200 keeps ramps short enough to
    see clearly on a 20-minute chart.

    Expected visual:
      Upper trace:
        T+0→T+1m    unconstrained (10000 W)
        T+1m        DERC4 received → ramp down to 0 W (50 s, AS4777 wGra)
        T+1m→T+6m   0 W (disconnected + grace)
        T+6m        grace ends → ramp up to 20000 W (DERC5, 100 s)
        T+8m        DERC5 expires → ramp to 10000 W (unconstrained, 50 s)
        T+9m        DERC6 received → ramp down to 5000 W (25 s)
        T+13m       DERC6 expires → ramp back to 10000 W (25 s)
      Lower trace: flat at −10000 W (no import controls or defaults)
      Step strips: GET-DERC-4 / GET-DERC-5 / WAIT-OBSERVE-DERC-5 /
                   GET-DERC-6 / WAIT-OBSERVE-DERC-6 / WAIT-OBSERVE-DERP-1-6-DEFAULTS
      Orange receipt markers at T+1m (grp 1), T+1m30s (grp 2), T+9m (grp 2).
    """
    test_end = T0 + timedelta(minutes=20)

    async with generate_async_session(pg_envoy_base_config) as session:
        site = _make_site_with_setting(aggregator_id=1, max_w=10000, grad_w=200)
        session.add(site)
        # Group 1 = FSA1 / DERP1, high priority. No export default → group 2 can win after DERC4.
        grp1 = generate_class_instance(SiteControlGroup, seed=1, site_control_group_id=1, primacy=1)
        # Group 2 = FSA2 / DERP6, lower priority, holds the export controls.
        grp2 = generate_class_instance(SiteControlGroup, seed=2, site_control_group_id=2, primacy=2)
        session.add_all([grp1, grp2])

        # DERC4: opModConnect=False + genLim=0 on group 1 (T+1m to T+5m)
        # offset=1 so created_time=T0+30s (after test_start); 4min duration keeps end at T+5m.
        derc4 = _make_doe(
            site,
            grp1,
            offset_minutes=1,
            duration_minutes=4,
            gen_limit=Decimal("0"),
            set_connected=False,
            seed=40,
        )
        # DERC5: export 200% on group 2 (T+1m to T+8m — ends just before DERC6 starts)
        # offset=1 so created_time=T0+30s; 7min duration keeps end at T+8m.
        derc5 = _make_doe(
            site,
            grp2,
            offset_minutes=1,
            duration_minutes=7,
            export_limit=Decimal("20000"),
            seed=50,
        )
        # DERC6: export 50% on group 2 (5 min — non-overlapping with DERC5)
        derc6 = _make_doe(
            site,
            grp2,
            offset_minutes=8,
            duration_minutes=5,
            export_limit=Decimal("5000"),
            seed=60,
        )
        session.add_all([derc4, derc5, derc6])
        await session.flush()
        ct4, ct5, ct6 = derc4.created_time, derc5.created_time, derc6.created_time
        await session.commit()

    polls = [
        # T+1m: device polls /derp/1/derc — DERC4 received (triggers disconnect)
        # ct4 = T0+30s, so ct4+30s = T0+1m (= DERC4 start_time → effective_start = T0+1m)
        _poll(1, ct4 + timedelta(seconds=30), req_id=1, step_name="GET-DERC-4"),
        # T+1m30s: device polls /derp/2/derc — DERC5 received (masked by disconnect until T+6m)
        # ct5 = T0+30s, so ct5+60s = T0+1m30s
        _poll(2, ct5 + timedelta(minutes=1), req_id=2, step_name="GET-DERC-5"),
        # T+7m: re-poll during wait step — device should now be following DERC5 (200%)
        _poll(2, T0 + timedelta(minutes=7), req_id=3, step_name="WAIT-OBSERVE-DERC-5"),
        # T+9m: device polls /derp/2/derc — DERC6 received (DERC5 already expired at T+8m)
        _poll(2, ct6 + timedelta(minutes=1, seconds=30), req_id=4, step_name="GET-DERC-6"),
        # T+11m: re-poll during wait step — device should be following DERC6 (50%)
        _poll(2, T0 + timedelta(minutes=11), req_id=5, step_name="WAIT-OBSERVE-DERC-6"),
        # T+15m: poll after DERC6 expires — device returns to unconstrained
        _poll(
            1,
            T0 + timedelta(minutes=15),
            req_id=6,
            step_name="WAIT-OBSERVE-DERP-1-6-DEFAULTS",
        ),
    ]

    async with generate_async_session(pg_envoy_base_config) as session:
        html = await generate_power_limit_chart_html(session, T0, test_end, polls)

    assert html is not None
    assert "Device Power Chart" in html
    out = _out("scenario_E_gen10_derc4560.html")
    out.write_text(html)
    print(f"\n  ✓ Scenario E → {out}")


# ─── Scenario E2: GEN-10 DERC4/5/6 — subscription variant (no gap) ───────────


async def test_chart_gen10_derc456_subscribed(pg_envoy_base_config):
    """
    Subscription variant of test_chart_gen10_derc456.

    Identical DERC4/5/6 setup but both groups are subscribed — controls are received
    at created_time (notification delivery assumed instant):

      DERC4 effective_start = T+1m  (created_time T+0m30s < start_time T+1m)
      DERC5 effective_start = T+1m  (same created_time as DERC4)
      DERC6 effective_start = T+8m  (created_time T+7m30s < start_time T+8m)

    Key difference from the polled scenario: DERC6 is effective from T+8m (its
    start_time) so there is NO gap between DERC5 and DERC6 in the Controls strip.

    Expected visual:
      Upper trace:
        T+0→T+1m    unconstrained (10000 W)
        T+1m        DERC4 received (notification) → instant to 0 W (disconnect)
        T+1m→T+6m   0 W (disconnected + grace)
        T+6m        grace ends → ramp up to 10000 W (DERC5 capped at setMaxW, 50 s)
        T+8m        DERC5 expires / DERC6 starts → ramp to 5000 W (25 s, contiguous)
        T+13m       DERC6 expires → ramp back to 10000 W (25 s)
      Controls strip: GET-DERC-4 (T+1m→T+5m) / GET-DERC-5 (T+5m→T+8m) / GET-DERC-6 (no gap between DERC5→6)
      Green receipt markers at T+0m30s (grp 1 + grp 2) and T+7m30s (grp 2).
    """
    test_end = T0 + timedelta(minutes=20)

    async with generate_async_session(pg_envoy_base_config) as session:
        site = _make_site_with_setting(aggregator_id=1, max_w=10000, grad_w=200)
        session.add(site)
        grp1 = generate_class_instance(SiteControlGroup, seed=1, site_control_group_id=1, primacy=1)
        grp2 = generate_class_instance(SiteControlGroup, seed=2, site_control_group_id=2, primacy=2)
        session.add_all([grp1, grp2])

        derc4 = _make_doe(
            site,
            grp1,
            offset_minutes=1,
            duration_minutes=4,
            gen_limit=Decimal("0"),
            set_connected=False,
            seed=40,
        )
        derc5 = _make_doe(
            site,
            grp2,
            offset_minutes=1,
            duration_minutes=7,
            export_limit=Decimal("20000"),
            seed=50,
        )
        derc6 = _make_doe(
            site,
            grp2,
            offset_minutes=8,
            duration_minutes=5,
            export_limit=Decimal("5000"),
            seed=60,
        )
        session.add_all([derc4, derc5, derc6])

        # Both groups subscribed — receipt = created_time for all controls
        session.add_all([_make_subscription(1), _make_subscription(2)])

        await session.flush()
        ct4, ct6 = derc4.created_time, derc6.created_time
        await session.commit()

    # No DERC polls needed (subscribed). Requests carry step names for strip labelling:
    # step_name for each DOE = last request to that group's DERC path at or before created_time.
    polls = [
        # ct4 = T0+30s: DERC4 (grp1) and DERC5 (grp2) both created here.
        # Each group gets step_name from its own DERC-path request.
        _poll(1, ct4, req_id=1, step_name="GET-DERC-4"),
        _poll(2, ct4, req_id=2, step_name="GET-DERC-5"),
        _poll(2, T0 + timedelta(minutes=7), req_id=3, step_name="WAIT-OBSERVE-DERC-5"),
        # ct6 = T0+7m30s: DERC6 created here → gets "GET-DERC-6"
        _poll(2, ct6, req_id=4, step_name="GET-DERC-6"),
        _poll(2, T0 + timedelta(minutes=11), req_id=5, step_name="WAIT-OBSERVE-DERC-6"),
        _poll(
            1,
            T0 + timedelta(minutes=15),
            req_id=6,
            step_name="WAIT-OBSERVE-DERP-1-6-DEFAULTS",
        ),
    ]

    async with generate_async_session(pg_envoy_base_config) as session:
        html = await generate_power_limit_chart_html(session, T0, test_end, polls)

    assert html is not None
    assert "Device Power Chart" in html
    out = _out("scenario_E2_gen10_derc456_subscribed0.html")
    out.write_text(html)
    print(f"\n  ✓ Scenario E2 → {out}")


# ─── Scenario F: opModEnergise — de-energise and re-energise grace period ─────


async def test_chart_op_mod_energise(pg_envoy_base_config):
    """
    Demonstrates opModEnergise=False de-energise (power=0) and 1-minute grace after
    explicit True-control re-energise, mirroring the opModConnect behaviour.

    Program 1:
      - Default export=7000W
      - T+5m: export control 5000W begins (spanning full test)
      - T+10m: opModEnergise=False (duration 5min, expires T+15m) → power forced to 0
      - T+15m: False control expires → re-energise triggered, 1-min grace (power still 0)
      - T+16m: grace ends → resumes 5000W export control
      - T+20m: opModEnergise=True (already re-energised, no effect here)

    Expected visual:
      - Upper trace: 5000W from T+5m, drops to 0 at T+10m, ramps back to 5000W at T+16m
      - Lower trace: flat at -10000W (no import limit set)
    """
    test_end = T0 + timedelta(minutes=35)
    created_times: dict[str, datetime] = {}

    async with generate_async_session(pg_envoy_base_config) as session:
        site = _make_site_with_setting(aggregator_id=1)
        session.add(site)
        grp1 = generate_class_instance(SiteControlGroup, seed=1, site_control_group_id=1, primacy=1)
        session.add(grp1)

        session.add(
            generate_class_instance(
                SiteControlGroupDefault,
                seed=1,
                site_control_group=grp1,
                import_limit_active_watts=None,
                export_limit_active_watts=Decimal("7000"),
                generation_limit_active_watts=None,
                load_limit_active_watts=None,
                ramp_rate_percent_per_second=None,
                storage_target_active_watts=None,
                changed_time=T0 - timedelta(minutes=1),
            )
        )

        ctrls = {
            "export": _make_doe(
                site,
                grp1,
                offset_minutes=5,
                duration_minutes=25,
                export_limit=Decimal("5000"),
                seed=10,
            ),
            "de-energise": _make_doe(
                site,
                grp1,
                offset_minutes=10,
                duration_minutes=5,
                set_energized=False,
                seed=20,
            ),
            "re-energise": _make_doe(
                site,
                grp1,
                offset_minutes=20,
                duration_minutes=5,
                set_energized=True,
                seed=30,
            ),
        }
        session.add_all(ctrls.values())
        await session.flush()
        created_times = {k: v.created_time for k, v in ctrls.items()}
        await session.commit()

    polls = [
        _dderc_poll(1, T0 + timedelta(seconds=5), req_id=0),
        _poll(1, created_times["export"] + timedelta(seconds=60), req_id=1),
        _poll(1, created_times["de-energise"] + timedelta(seconds=60), req_id=2),
        _poll(1, created_times["re-energise"] + timedelta(seconds=60), req_id=3),
    ]

    async with generate_async_session(pg_envoy_base_config) as session:
        html = await generate_power_limit_chart_html(session, T0, test_end, polls)

    assert html is not None
    assert "Device Power Chart" in html
    out = _out("scenario_F_op_mod_energise0.html")
    out.write_text(html)
    print(f"\n  ✓ Scenario F → {out}")


# ─── Scenario G: ALL-28 — cancellation hands over to a CHANGED default ────────


async def test_chart_all28_cancellation_to_changed_default(pg_envoy_base_config):
    """
    Reproduces ALL-28 steps (e)-(l): the default is changed (setGradW=100 → 1%/s) while DERC3
    is active; DERC3 is then cancelled; the device must ramp to the 0W default at 1%/s from the
    poll where it OBSERVES the cancellation (not the server-side deletion moment), then ramp to
    DERC4 at the same 1%/s.

    Timeline (setMaxW=10000, DERC polls every 60s at :30 offsets):
      - T+1m:     dderc poll → default (imp=0, exp=0, no setGradW) becomes known
      - T+3m:     DERC3 (exp/imp 5000, 15min duration) starts (polled at T+2m30s)
      - T+7m:     default changed to imp=0 / exp=0 / setGradW=100
      - T+7m10s:  dderc poll → changed default becomes known (DERC3 active → no ramp yet)
      - T+8m:     DERC3 cancelled (deleted server-side)
      - T+8m30s:  poll reveals the cancellation → ramp 5000→0 W at 1%/s (50s)
      - T+11m:    DERC4 (exp/imp 3000) starts (polled T+10m30s) → ramp 0→3000 W at 1%/s (30s)
    """
    test_end = T0 + timedelta(minutes=16)
    default_changed_at = T0 + timedelta(minutes=7)
    derc3_cancelled_at = T0 + timedelta(minutes=8)

    async with generate_async_session(pg_envoy_base_config) as session:
        site = _make_site_with_setting(aggregator_id=1)
        session.add(site)
        grp1 = generate_class_instance(SiteControlGroup, seed=1, site_control_group_id=1, primacy=1)
        session.add(grp1)
        await session.flush()

        # Old default (imp=0, exp=0, no setGradW) — archived when the default was changed at T+7m
        session.add(
            generate_class_instance(
                ArchiveSiteControlGroupDefault,
                seed=1,
                site_control_group_id=1,
                import_limit_active_watts=Decimal("0"),
                export_limit_active_watts=Decimal("0"),
                generation_limit_active_watts=None,
                load_limit_active_watts=None,
                ramp_rate_percent_per_second=None,
                storage_target_active_watts=None,
                changed_time=T0 - timedelta(minutes=1),
                archive_time=default_changed_at,
                deleted_time=None,
            )
        )
        # New default (imp=0, exp=0, setGradW=100 → 1%/s) — active from T+7m
        session.add(
            generate_class_instance(
                SiteControlGroupDefault,
                seed=2,
                site_control_group=grp1,
                import_limit_active_watts=Decimal("0"),
                export_limit_active_watts=Decimal("0"),
                generation_limit_active_watts=None,
                load_limit_active_watts=None,
                ramp_rate_percent_per_second=100,
                storage_target_active_watts=None,
                changed_time=default_changed_at,
            )
        )

        # DERC3: 50% limits, deliberately long duration, cancelled (deleted) at T+8m
        session.add(
            _make_archive_doe(
                site_id=site.site_id,
                group_id=1,
                doe_id=333,
                start=T0 + timedelta(minutes=3),
                duration_seconds=900,
                export_limit=Decimal("5000"),
                import_limit=Decimal("5000"),
                deleted_time=derc3_cancelled_at,
                seed=3,
            )
        )
        # DERC4: 30% limits, created at T+10m30s, starts T+11m
        derc4 = _make_doe(
            site,
            grp1,
            offset_minutes=11,
            duration_minutes=5,
            export_limit=Decimal("3000"),
            import_limit=Decimal("3000"),
            seed=4,
        )
        session.add(derc4)
        await session.commit()

    polls = [_poll(1, T0 + timedelta(seconds=30 + k * 60), req_id=k) for k in range(16)]
    polls.append(_dderc_poll(1, T0 + timedelta(minutes=1), req_id=100))
    polls.append(_dderc_poll(1, T0 + timedelta(minutes=7, seconds=10), req_id=101))

    async with generate_async_session(pg_envoy_base_config) as session:
        html = await generate_power_limit_chart_html(session, T0, test_end, polls)

    assert html is not None
    assert "Device Power Chart" in html
    out = _out("scenario_G_all28_cancel_to_changed_default0.html")
    out.write_text(html)
    print(f"\n  ✓ Scenario G → {out}")
    print(f"\n  Open all charts: ls {OUTPUT_DIR}/")

    # Plotly embeds hover text in JSON where < and > are escaped
    def _hover_in_html(hover: str) -> bool:
        return hover.replace("<", "\\u003c").replace(">", "\\u003e") in html

    # The ramp to the 0W default starts at T+8m30s (the poll that reveals the cancellation),
    # not at the T+8m server-side deletion — and runs at the CHANGED default's 1%/s.
    assert _hover_in_html(
        "Control received: Default DERP1<br>Relative time: 8:30<br>"
        "Ramping from 5000 W to 0 W<br>Ramp rate: Default setGradW=100 (50s)"
    )
    # DERC4 has no rampTms, so it also ramps at the changed default's 1%/s.
    assert _hover_in_html("Ramping from 0 W to 3000 W<br>Ramp rate: Default setGradW=100 (30s)")
