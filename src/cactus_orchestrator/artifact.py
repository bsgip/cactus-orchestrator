import io
import logging
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime

from cactus_runner.models import ReportingData
from sqlalchemy.ext.asyncio import AsyncSession

from cactus_orchestrator.crud import (
    create_run_report_generation_record,
    select_playlist_position_label,
    select_run_group_for_user,
    select_user_from_run_group,
    update_runartifact_with_file_data,
)
from cactus_orchestrator.model import (
    ComplianceRecord,
    ComplianceRequest,
    Run,
    RunArtifact,
    User,
)
from cactus_orchestrator.reporting.compliance import (
    determine_compliance,
    get_compliance_for_run_group,
    get_procedure_mapping,
)
from cactus_orchestrator.reporting.compliance_reporting import pdf_report_as_bytes
from cactus_orchestrator.reporting.deprecated_compliance_reporting import (
    pdf_report_as_bytes as deprecated_pdf_report_as_bytes,
)
from cactus_orchestrator.reporting.generate import generate_pdf_report_v1

logger = logging.getLogger(__name__)


@dataclass
class Artifact:
    file_data: bytes
    mime_type: str


def _add_text_file_to_zip_data(zip_data: bytes, filename: str, content: str) -> bytes:
    """Adds (or replaces) a text file entry in a zip archive."""
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as updated_zip:
        with zipfile.ZipFile(io.BytesIO(zip_data)) as original_zip:
            for member in original_zip.namelist():
                if member != filename:
                    with updated_zip.open(member, "w") as member_handle:
                        member_handle.write(original_zip.read(member))
        updated_zip.writestr(filename, content)
    return zip_buffer.getvalue()


async def regenerate_run_artifact(
    session: AsyncSession, run: Run, run_artifact: RunArtifact, deploy_release_tag: str | None = None
) -> RunArtifact:
    """Regenerates the RunArtifact.

    - Uses the reporting data to (re)generate the run report.
    - Replaces the run report in the file data of `run_artifact`.
    - Updates the run artifact in the orchestrator database (to reflect the new file data).
    - Adds an entry to the RunReportGeneration table to record the fact the report was regenerated.

    Args:
        session: A database session.
        run (Run): The Run the artifact belongs to.
        run_artifact (RunArtifact): The RunArtifact to update.
        deploy_release_tag (str | None): the cactus-deploy release tag that was live for this run's pod
            (Run.deploy_release_tag).
    Returns:
        RunArtifact: the updated RunArtifact
    Raises:
        ValueError: if regeneration of pdf report fails
    """

    playlist_info = await select_playlist_position_label(session, run)

    # Callers (e.g. admin endpoint) guard reporting_data/version for None before calling: ignore
    updated_zip_data = await regenerate_pdf_report(
        file_data=run_artifact.file_data,
        raw_reporting_data=run_artifact.reporting_data,  # ty: ignore[invalid-argument-type]
        version=run_artifact.version,  # ty: ignore[invalid-argument-type]
        playlist_info=playlist_info,
        deploy_release_tag=deploy_release_tag,
    )

    # Update the file data
    await update_runartifact_with_file_data(session=session, run_artifact=run_artifact, file_data=updated_zip_data)

    # Record the successful regeneration
    await create_run_report_generation_record(session=session, run_artifact_id=run_artifact.run_artifact_id)

    return run_artifact
