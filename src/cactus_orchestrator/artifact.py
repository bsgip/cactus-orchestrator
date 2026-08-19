import logging
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from cactus_orchestrator.crud import (
    select_deploy_release_at,
    select_playlist_position_label,
    select_user_run_with_artifact,
)
from cactus_orchestrator.filestore import (
    fetch_run_finalised_file,
    fetch_run_zip,
    list_run_finalised_files,
    run_report_exists,
    run_zip_exists,
    save_run_report,
)
from cactus_orchestrator.model import Run, User
from cactus_orchestrator.reporting.generate import generate_pdf_report
from cactus_orchestrator.settings import CactusOrchestratorSettings

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RawReportingData:
    raw_json: str
    version: int


@dataclass(frozen=True)
class EnvoyDbDump:
    schema_sql: str
    data_sql: str


def fetch_run_envoy_db(settings: CactusOrchestratorSettings, run_id: int) -> EnvoyDbDump | None:
    """Fetches the envoy database dump returned by the runner during finalisation"""
    schema_files = list_run_finalised_files(settings.file_store_path, run_id, filter="EnvoyDBSchema_*.dump")
    data_files = list_run_finalised_files(settings.file_store_path, run_id, filter="EnvoyDB_*.dump")

    if len(schema_files) == 0 or len(data_files) == 0:
        return None

    with open(schema_files[0]) as fp:
        schema_sql = fp.read()

    with open(data_files[0]) as fp:
        data_sql = fp.read()

    return EnvoyDbDump(schema_sql=schema_sql, data_sql=data_sql)


def fetch_run_reporting_data_json(settings: CactusOrchestratorSettings, run_id: int) -> RawReportingData | None:
    """Fetches the reporting data JSON (string encoded) as returned by the runner during finalisation"""
    reporting_data_files = list_run_finalised_files(settings.file_store_path, run_id, filter="ReportingData_v*.json")
    if len(reporting_data_files) > 0:
        data_file = reporting_data_files[0]
        reporting_data = fetch_run_finalised_file(settings.file_store_path, run_id, data_file)
        if reporting_data is not None:
            raw_json = reporting_data.decode()

            # There is a "version" attribute in the JSON but to save us loading the whole lot into memory
            # lets look at the naming convention on the file
            if "_v1_" in data_file.name:
                version = 1
            else:
                raise Exception(f"Couldn't extract version from {reporting_data_files}")
            return RawReportingData(raw_json, version)
    return None


async def fetch_run_artifact_zip(
    session: AsyncSession, user: User, settings: CactusOrchestratorSettings, run: Run, force_regenerate: bool = False
) -> bytes | None:
    """Fetches the report + finalisation data for a specific run. If there is no report on record - it will also
    attempt to be generated. Can return None if there is nothing on record for the run

    force_regenerate: If True - the PDF will be generated, updating any existing one"""

    if not run_zip_exists(settings.file_store_path, run.run_id):
        # There might be an un-migrated artifact
        # This is all temporary - once fully migrated we should just return None here
        if run.run_artifact_id is not None and not run.run_artifact_migrated:
            return (await select_user_run_with_artifact(session, user.user_id, run.run_id)).run_artifact.file_data
        return None

    # If there is no run report data yet - it's time to generate one from the finalisation data
    generation_errors: list[str] | None = None
    if force_regenerate or not run_report_exists(settings.file_store_path, run.run_id):
        # There should be a file with reporting data returned in the runner finalisation data
        reporting_data = fetch_run_reporting_data_json(settings, run.run_id)

        # Generate the pdf run report and save it.
        # Only attempt generation if there is reporting data.
        if reporting_data:
            logger.info(
                f"PDF Report for run {run.run_id} will be generated."
                + f" Found v{reporting_data.version} set of {len(reporting_data.raw_json)} json chars."
            )
            try:
                playlist_info = await select_playlist_position_label(session, run)
                deploy_release = await select_deploy_release_at(session, run.created_at)
                pdf_file_data = await generate_pdf_report(
                    raw_reporting_data=reporting_data.raw_json,
                    raw_reporting_data_version=reporting_data.version,
                    playlist_info=playlist_info,
                    deploy_release_tag=deploy_release.release_tag if deploy_release else None,
                )

                save_run_report(settings.file_store_path, run.run_id, pdf_file_data)
            except Exception as exc:
                msg = f"Unable to generate run report for run {run.run_id}. Reason={exc}"
                logger.error(msg, exc_info=exc)
                generation_errors = [msg]
        else:
            logger.info(f"PDF Report for run {run.run_id} could not be generated - no reporting data in store.")

    return fetch_run_zip(settings.file_store_path, run.run_id, generation_errors)
