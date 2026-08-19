import asyncio
import json
import logging
import subprocess  # nosec B404
import time
from datetime import datetime
from typing import Any

import testing.postgresql
from cactus_runner.models import ReportingData
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from cactus_orchestrator.artifact import fetch_run_envoy_db, fetch_run_reporting_data_json
from cactus_orchestrator.power_limit_chart import generate_power_limit_chart_html
from cactus_orchestrator.settings import CactusOrchestratorSettings

logger = logging.getLogger(__name__)


def _patch_legacy_site_der_id(data: dict | list | str) -> Any:  # noqa: ANN401
    """Renames the legacy 'siteDerId' key to 'siteId' throughout nested dicts/lists, in place.

    cactus-runner (Envoy v1.5.0, cactus-runner#192) renamed SiteDERRating/SiteDERSetting/
    SiteDERAvailability/SiteDERStatus.site_der_id -> site_id. ReportingData_v1 blobs captured by an
    older runner still serialize the old key and fail to deserialize against the current model.
    This lets old artifacts keep loading without requiring changes in cactus-runner itself.
    """
    if isinstance(data, dict):
        if "siteDerId" in data and "siteId" not in data:
            data["siteId"] = data["siteDerId"]
        for value in data.values():
            _patch_legacy_site_der_id(value)
    elif isinstance(data, list):
        for item in data:
            _patch_legacy_site_der_id(item)
    return data


async def generate_power_limit_chart(
    settings: CactusOrchestratorSettings, run_id: int, video_start_seconds: float | None = None
) -> str | None:
    """Generate a standalone power limit HTML chart from the dumps stored in a RunArtifact.

    Spins up an ephemeral local postgres process (via testing.postgresql), restores the
    envoy schema and data dumps, queries the DB, then tears the process down.

    Returns the HTML string, or None if the artifact lacks sufficient DER data to build
    the chart (e.g. no SiteDERSettings or SiteControlGroups were ever created).

    Raises ValueError if the artifact pre-dates power limit chart support (no dumps present),
    if the reporting data cannot be deserialized, or if the client never polled/subscribed to
    a control list despite controls existing (non-compliant client; knowledge cannot be modelled).
    """

    raw_reporting_data = fetch_run_reporting_data_json(settings, run_id)
    if raw_reporting_data is None:
        raise ValueError(f"Couldn't extract runner reporting data for run {run_id}")

    envoy_dump = fetch_run_envoy_db(settings, run_id)
    if envoy_dump is None:
        raise ValueError(f"Couldn't extract envoy database dump for run {run_id}")

    try:
        # Callers (e.g. admin endpoint) guard reporting_data/version for None before calling: ignore
        reporting_data = ReportingData.from_json(raw_reporting_data.version, raw_reporting_data.raw_json)
    except Exception as first_exc:
        try:
            patched = json.dumps(_patch_legacy_site_der_id(json.loads(raw_reporting_data.raw_json)))
            reporting_data = ReportingData.from_json(raw_reporting_data.version, patched)
        except Exception:
            raise ValueError(f"Failed to deserialize reporting data: {first_exc}") from first_exc

    test_start: datetime | None = reporting_data.runner_state.active_test_procedure.started_at
    if test_start is None:
        logger.warning("power_limit_chart: test procedure has no started_at - skipping chart")
        return None
    test_end: datetime = reporting_data.created_at
    request_history = reporting_data.runner_state.request_history

    # Build doe_id → tag from the runner's tag → doe_id annotation map (inverted).
    # This allows the chart to label each control by its YAML tag rather than inferring
    # a step name from request timestamps (which is fragile when controls are created
    # during the same request that polls the DERC list).
    tag_by_alias = reporting_data.runner_state.active_test_procedure.resource_annotations.der_control_ids_by_alias
    doe_tags: dict[int, str] = {doe_id: tag for tag, doe_id in tag_by_alias.items()}

    step_completions: list[tuple[str, datetime]] = [
        (name, info.completed_at)
        for name, info in reporting_data.runner_state.active_test_procedure.step_status.items()
        if info.completed_at is not None
    ]

    t0 = time.monotonic()
    timings: list[tuple[str, float]] = []

    try:
        # on hosts with slow fsync initdb's default sync of ~1000 files turns ~0.3s into ~20s.
        pg: testing.postgresql.Postgresql = await asyncio.to_thread(
            testing.postgresql.Postgresql, initdb_args="-U postgres -A trust --no-sync"
        )
    except RuntimeError as exc:
        raise ValueError(f"Postgres unavailable (is initdb installed?): {exc}") from exc
    timings.append(("pg-start", time.monotonic() - t0))
    try:
        pg_url: str = pg.url()
        async_pg_url = pg_url.replace("postgresql://", "postgresql+asyncpg://")

        for label, sql in (("schema-restore", envoy_dump.schema_sql), ("data-restore", envoy_dump.data_sql)):
            # psql is the canonical restore tool for plain-SQL pg_dump output; nosec B603 B607
            proc = await asyncio.to_thread(
                subprocess.run,
                ["psql", pg_url],
                input=sql.encode(),
                capture_output=True,
            )
            timings.append((label, time.monotonic() - t0))
            if proc.returncode != 0:
                stderr_str = (
                    proc.stderr.decode(errors="replace") if isinstance(proc.stderr, bytes) else str(proc.stderr)
                )
                logger.error("psql restore failed (exit %d): %s", proc.returncode, stderr_str)
                proc.check_returncode()

        engine = create_async_engine(async_pg_url)
        try:
            session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
            async with session_factory() as session:
                return await generate_power_limit_chart_html(
                    session,
                    test_start,
                    test_end,
                    request_history,
                    test_name=reporting_data.runner_state.active_test_procedure.name,
                    doe_tags=doe_tags,
                    video_start_seconds=video_start_seconds,
                    step_completions=step_completions,
                )
        finally:
            await engine.dispose()
            timings.append(("chart-gen", time.monotonic() - t0))
    finally:
        await asyncio.to_thread(pg.stop)
        timings.append(("pg-stop", time.monotonic() - t0))
        breakdown = ", ".join(f"{name} +{offset:.2f}s" for name, offset in timings)
        logger.info(f"power_limit_chart timing for {run_id=}: {breakdown}")
