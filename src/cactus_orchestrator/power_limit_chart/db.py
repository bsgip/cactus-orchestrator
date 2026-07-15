"""Raw row types and queries against a restored envoy DB dump.

The SQL here uses explicit column selection (not the envoy ORM models) so the chart keeps
working against dumps taken from older envoy schema versions. Changing the row dataclasses
or queries has backwards compatibility considerations with old versions of the envoy DB schema.
"""

from dataclasses import dataclass
from datetime import datetime

from envoy.server.model.subscription import SubscriptionResource
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


@dataclass
class _RawDERSetting:
    max_w_value: int
    max_w_multiplier: int
    max_charge_rate_w_value: int | None
    max_charge_rate_w_multiplier: int | None
    max_discharge_rate_w_value: int | None
    max_discharge_rate_w_multiplier: int | None


@dataclass
class _RawControlGroup:
    site_control_group_id: int
    primacy: int


@dataclass
class _RawDOE:
    """Minimal DOE columns fetched from either the active or archive DOE table."""

    dynamic_operating_envelope_id: int
    site_control_group_id: int
    created_time: datetime
    start_time: datetime
    duration_seconds: int
    superseded: bool
    export_limit_watts: float | None
    generation_limit_active_watts: float | None
    import_limit_active_watts: float | None
    load_limit_active_watts: float | None
    set_connected: bool | None
    set_energized: bool | None
    ramp_time_seconds: float | None
    storage_target_active_watts: float | None
    is_archive: bool
    deleted_time: datetime | None  # archive rows only
    archive_time: datetime | None  # archive rows only


@dataclass
class _RawDefault:
    """Minimal site-control-default columns from the active or archive default table."""

    site_control_group_id: int
    changed_time: datetime
    export_limit_active_watts: float | None
    generation_limit_active_watts: float | None
    import_limit_active_watts: float | None
    load_limit_active_watts: float | None
    ramp_rate_percent_per_second: int | None
    storage_target_active_watts: float | None
    is_archive: bool
    deleted_time: datetime | None  # archive rows only
    archive_time: datetime | None  # archive rows only


async def _check_has_legacy_site_der_table(session: AsyncSession) -> bool:
    """Returns True if site_der_setting still uses the pre-flatten schema (site_der_id FK to a
    parent site_der table, dropped in envoy migration b2f4a6c8d1e3_drop_site_der) rather than a
    direct site_id column."""
    result = await session.execute(
        text(
            "SELECT COUNT(*) FROM information_schema.columns "
            "WHERE table_name = 'site_der_setting' AND column_name = 'site_der_id'"
        )
    )
    return (result.scalar() or 0) > 0


async def _get_der_setting(session: AsyncSession) -> _RawDERSetting | None:
    setting_cols = (
        "sds.max_w_value, sds.max_w_multiplier, "
        "sds.max_charge_rate_w_value, sds.max_charge_rate_w_multiplier, "
        "sds.max_discharge_rate_w_value, sds.max_discharge_rate_w_multiplier"
    )
    if await _check_has_legacy_site_der_table(session):
        query = f"""
SELECT {setting_cols}
FROM site_der_setting sds
JOIN site_der sd ON sd.site_der_id = sds.site_der_id
WHERE sd.site_id = (SELECT site_id FROM site ORDER BY changed_time DESC LIMIT 1)
LIMIT 1
            """  # noqa: S608  # nosec B608
    else:
        query = f"""
SELECT {setting_cols}
FROM site_der_setting sds
WHERE sds.site_id = (SELECT site_id FROM site ORDER BY changed_time DESC LIMIT 1)
LIMIT 1
            """  # noqa: S608  # nosec B608
    result = await session.execute(text(query))
    row = result.first()
    if row is None:
        return None
    return _RawDERSetting(
        max_w_value=row.max_w_value,
        max_w_multiplier=row.max_w_multiplier,
        max_charge_rate_w_value=row.max_charge_rate_w_value,
        max_charge_rate_w_multiplier=row.max_charge_rate_w_multiplier,
        max_discharge_rate_w_value=row.max_discharge_rate_w_value,
        max_discharge_rate_w_multiplier=row.max_discharge_rate_w_multiplier,
    )


async def _get_control_groups(session: AsyncSession) -> list[_RawControlGroup]:
    result = await session.execute(text("SELECT site_control_group_id, primacy FROM site_control_group"))
    return [_RawControlGroup(site_control_group_id=row.site_control_group_id, primacy=row.primacy) for row in result]


async def _get_subscribed_group_ids(
    session: AsyncSession, resource: SubscriptionResource = SubscriptionResource.DYNAMIC_OPERATING_ENVELOPE
) -> set[int]:
    """Returns site_control_group_ids for which an active subscription of the given type exists.
    Only subscriptions with an explicit resource_id are considered; 0 subscriptions is valid
    (device relies entirely on polling)."""
    result = await session.execute(
        text("SELECT resource_id FROM subscription WHERE resource_type = :rtype AND resource_id IS NOT NULL"),
        {"rtype": resource.value},
    )
    return {row.resource_id for row in result}


async def _check_has_storage_target(session: AsyncSession) -> bool:
    """Returns True if both DOE tables include storage_target_active_watts (v1.3+ schema)."""
    result = await session.execute(
        text(
            "SELECT COUNT(*) FROM information_schema.columns "
            "WHERE table_name IN ('dynamic_operating_envelope', 'archive_dynamic_operating_envelope') "
            "AND column_name = 'storage_target_active_watts'"
        )
    )
    return (result.scalar() or 0) >= 2


async def _get_does(session: AsyncSession, has_storage_target: bool) -> list[_RawDOE]:
    """Fetch all active and archived DOEs for the active site using explicit column selection."""
    storage_col = "storage_target_active_watts" if has_storage_target else "NULL AS storage_target_active_watts"
    result = await session.execute(
        text(
            f"""
SELECT
    dynamic_operating_envelope_id,
    site_control_group_id,
    created_time,
    start_time,
    duration_seconds,
    superseded,
    export_limit_watts,
    generation_limit_active_watts,
    import_limit_active_watts,
    load_limit_active_watts,
    set_connected,
    set_energized,
    ramp_time_seconds,
    {storage_col},
    false AS is_archive,
    NULL AS deleted_time,
    NULL AS archive_time
    FROM dynamic_operating_envelope
    WHERE site_id = (SELECT site_id FROM site ORDER BY changed_time DESC LIMIT 1)
UNION ALL
SELECT
    dynamic_operating_envelope_id,
    site_control_group_id,
    created_time,
    start_time,
    duration_seconds,
    superseded,
    export_limit_watts,
    generation_limit_active_watts,
    import_limit_active_watts,
    load_limit_active_watts,
    set_connected,
    set_energized,
    ramp_time_seconds,
    {storage_col},
    true AS is_archive,
    deleted_time,
    archive_time
    FROM archive_dynamic_operating_envelope
    WHERE site_id = (SELECT site_id FROM site ORDER BY changed_time DESC LIMIT 1)
            """  # noqa: S608  # nosec B608
        )
    )
    does: list[_RawDOE] = []
    for row in result:
        does.append(
            _RawDOE(
                dynamic_operating_envelope_id=row.dynamic_operating_envelope_id,
                site_control_group_id=row.site_control_group_id,
                created_time=row.created_time,
                start_time=row.start_time,
                duration_seconds=row.duration_seconds,
                superseded=bool(row.superseded),
                export_limit_watts=float(row.export_limit_watts) if row.export_limit_watts is not None else None,
                generation_limit_active_watts=float(row.generation_limit_active_watts)
                if row.generation_limit_active_watts is not None
                else None,
                import_limit_active_watts=float(row.import_limit_active_watts)
                if row.import_limit_active_watts is not None
                else None,
                load_limit_active_watts=float(row.load_limit_active_watts)
                if row.load_limit_active_watts is not None
                else None,
                set_connected=row.set_connected,
                set_energized=row.set_energized,
                ramp_time_seconds=float(row.ramp_time_seconds) if row.ramp_time_seconds is not None else None,
                storage_target_active_watts=float(row.storage_target_active_watts)
                if row.storage_target_active_watts is not None
                else None,
                is_archive=bool(row.is_archive),
                deleted_time=row.deleted_time,
                archive_time=row.archive_time,
            )
        )
    return does


async def _get_defaults(session: AsyncSession, has_storage_target: bool) -> list[_RawDefault]:
    """Fetch all active and archived SiteControlGroupDefaults using explicit column selection."""
    storage_col = "storage_target_active_watts" if has_storage_target else "NULL AS storage_target_active_watts"
    result = await session.execute(
        text(f"""
SELECT
    site_control_group_id,
    changed_time,
    export_limit_active_watts,
    generation_limit_active_watts,
    import_limit_active_watts,
    load_limit_active_watts,
    ramp_rate_percent_per_second,
    {storage_col},
    false AS is_archive,
    NULL AS deleted_time,
    NULL AS archive_time
    FROM site_control_group_default
UNION ALL
SELECT
    site_control_group_id,
    changed_time,
    export_limit_active_watts,
    generation_limit_active_watts,
    import_limit_active_watts,
    load_limit_active_watts,
    ramp_rate_percent_per_second,
    {storage_col},
    true AS is_archive,
    deleted_time,
    archive_time
    FROM archive_site_control_group_default
        """)  # noqa: S608  # nosec B608
    )
    defaults: list[_RawDefault] = []
    for row in result:
        defaults.append(
            _RawDefault(
                site_control_group_id=row.site_control_group_id,
                changed_time=row.changed_time,
                export_limit_active_watts=float(row.export_limit_active_watts)
                if row.export_limit_active_watts is not None
                else None,
                generation_limit_active_watts=float(row.generation_limit_active_watts)
                if row.generation_limit_active_watts is not None
                else None,
                import_limit_active_watts=float(row.import_limit_active_watts)
                if row.import_limit_active_watts is not None
                else None,
                load_limit_active_watts=float(row.load_limit_active_watts)
                if row.load_limit_active_watts is not None
                else None,
                ramp_rate_percent_per_second=row.ramp_rate_percent_per_second,
                storage_target_active_watts=float(row.storage_target_active_watts)
                if row.storage_target_active_watts is not None
                else None,
                is_archive=bool(row.is_archive),
                deleted_time=row.deleted_time,
                archive_time=row.archive_time,
            )
        )
    return defaults
