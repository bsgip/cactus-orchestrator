import asyncio
import io
import logging
import zipfile
from datetime import datetime

import asyncpg
import testing.postgresql
from cactus_runner.models import ReportingData
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from cactus_orchestrator.model import RunArtifact
from cactus_orchestrator.power_limit_chart import generate_power_limit_chart_html

logger = logging.getLogger(__name__)

_ENVOY_SCHEMA_DUMP_PREFIX = "EnvoyDBSchema"
_ENVOY_DATA_DUMP_PREFIX = "EnvoyDB"
_DUMP_SUFFIX = ".dump"

# pg_dump statements that may fail due to missing roles in a fresh temporary DB.
# These are non-critical (ownership/privileges) and can be safely skipped.
_IGNORABLE_STMT_PREFIXES = (
    "ALTER TABLE",
    "ALTER SEQUENCE",
    "ALTER TYPE",
    "GRANT",
    "REVOKE",
    "COMMENT ON",
)


def extract_envoy_dumps(zip_data: bytes) -> tuple[str, str]:
    """Extract the envoy schema-only and data-only SQL dumps from an artifact ZIP.

    Returns (schema_sql, data_sql) as decoded strings.
    Raises ValueError if either dump is absent — the artifact pre-dates this feature.
    """
    with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
        names = zf.namelist()
        schema_name = next(
            (n for n in names if n.startswith(_ENVOY_SCHEMA_DUMP_PREFIX) and n.endswith(_DUMP_SUFFIX)),
            None,
        )
        data_name = next(
            (
                n
                for n in names
                if n.startswith(_ENVOY_DATA_DUMP_PREFIX)
                and n.endswith(_DUMP_SUFFIX)
                and not n.startswith(_ENVOY_SCHEMA_DUMP_PREFIX)
            ),
            None,
        )
        if schema_name is None or data_name is None:
            raise ValueError(
                "Artifact does not contain envoy DB dumps (generated before power limit chart support was added)"
            )
        return zf.read(schema_name).decode(), zf.read(data_name).decode()


async def _restore_sql(conn: asyncpg.Connection, sql: str) -> None:  # type: ignore[type-arg]
    """Execute SQL statements from a pg_dump file against conn.

    Ownership and privilege statements that fail due to missing roles in the fresh temporary
    DB are logged as warnings and skipped. All other errors are re-raised.
    """
    for raw in sql.split(";\n"):
        stmt = raw.strip()
        if not stmt or stmt.startswith("--"):
            continue
        try:
            await conn.execute(stmt)
        except asyncpg.PostgresError as exc:
            stmt_upper = stmt.lstrip().upper()
            if any(stmt_upper.startswith(p) for p in _IGNORABLE_STMT_PREFIXES):
                logger.warning("Skipping non-critical SQL restore statement: %s", exc)
            else:
                raise


async def generate_power_limit_chart(run_artifact: RunArtifact) -> str | None:
    """Generate a standalone power limit HTML chart from the dumps stored in a RunArtifact.

    Spins up an ephemeral local postgres process (via testing.postgresql), restores the
    envoy schema and data dumps, queries the DB, then tears the process down.

    Returns the HTML string, or None if the artifact lacks sufficient DER data to build
    the chart (e.g. no SiteDERSettings or SiteControlGroups were ever created).

    Raises ValueError if the artifact pre-dates power limit chart support (no dumps present)
    or if the reporting data cannot be deserialized.
    """
    schema_sql, data_sql = extract_envoy_dumps(run_artifact.file_data)

    try:
        reporting_data = ReportingData.from_json(run_artifact.version, run_artifact.reporting_data)  # type: ignore
    except Exception as exc:
        raise ValueError(f"Failed to deserialize reporting data: {exc}") from exc

    test_start: datetime | None = reporting_data.runner_state.active_test_procedure.started_at
    if test_start is None:
        return None
    test_end: datetime = reporting_data.created_at
    request_history = reporting_data.runner_state.request_history

    pg: testing.postgresql.Postgresql = await asyncio.to_thread(testing.postgresql.Postgresql)  # type: ignore
    try:
        pg_url: str = pg.url()
        async_pg_url = pg_url.replace("postgresql://", "postgresql+asyncpg://")

        conn: asyncpg.Connection = await asyncpg.connect(pg_url)  # type: ignore[type-arg]
        try:
            await _restore_sql(conn, schema_sql)
            await _restore_sql(conn, data_sql)
        finally:
            await conn.close()

        engine = create_async_engine(async_pg_url)
        try:
            session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
            async with session_factory() as session:
                return await generate_power_limit_chart_html(session, test_start, test_end, request_history)
        finally:
            await engine.dispose()
    finally:
        await asyncio.to_thread(pg.stop)
