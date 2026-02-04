import io
import logging
import zipfile
from dataclasses import dataclass

from cactus_runner.models import ReportingData
from sqlalchemy.ext.asyncio import AsyncSession

from cactus_orchestrator.crud import (
    create_run_report_generation_record,
    select_run_group_for_user,
    select_user_from_run_group,
    update_runartifact_with_file_data,
)
from cactus_orchestrator.model import ComplianceRecord, RunArtifact, User
from cactus_orchestrator.reporting.compliance import get_compliance_for_run_group, get_procedure_mapping
from cactus_orchestrator.reporting.compliance_reporting import pdf_report_as_bytes
from cactus_orchestrator.reporting.generate import generate_pdf_report_from_run_artifact

logger = logging.getLogger(__name__)


@dataclass
class Artifact:
    file_data: bytes
    mime_type: str


async def generate_run_group_artifact(
    session: AsyncSession, run_group_id: int, requester: User, compliance_record: ComplianceRecord
) -> Artifact | None:

    # Get all the information required for the report
    user = await select_user_from_run_group(session=session, run_group_id=run_group_id)
    if user is None:
        raise Exception()
    run_group = await select_run_group_for_user(session=session, user_id=user.user_id, run_group_id=run_group_id)
    if run_group is None:
        raise Exception()

    compliance_by_class = await get_compliance_for_run_group(
        procedure_map=await get_procedure_mapping(session, run_group)
    )

    # Generate the report
    file_data = pdf_report_as_bytes(
        requester=requester,
        user=user,
        run_group=run_group,
        compliance_by_class=compliance_by_class,
        compliance_record=compliance_record,
    )

    if file_data is None:
        return None
    return Artifact(file_data=file_data, mime_type="application/pdf")


def replace_pdf_in_zip_data(pdf_data: bytes, zip_data: bytes, pdf_filename_prefix: str) -> bytes:
    """Replaces the existing pdfs in `zip_data` with the pdf bytes from `pdf_data`

    Since there could be more than one pdf in the existing archive, replacements will happen
    to any pdf file whose name starts with `pdf_filename_prefix`.

    Args:
        pdf_data (bytes): the replacement pdf data
        zip_data (bytes): a zip file as bytes containing the pdf you want to replace
        pdf_filename_prefix (): Use to identify which pdf files get replaced

    Returns:
        bytes: a zip file as bytes containing all the previous files but with matching pdf files
        replaced
    """

    original_zip = zipfile.ZipFile(io.BytesIO(zip_data))

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as updated_zip:

        with zipfile.ZipFile(io.BytesIO(zip_data)) as original_zip:
            for member in original_zip.namelist():
                with updated_zip.open(member, "w") as member_handle:
                    if member.startswith(pdf_filename_prefix) and member.endswith("pdf"):
                        member_handle.write(pdf_data)
                    else:
                        member_handle.write(original_zip.read(member))

    updated_zip_data: bytes = zip_buffer.getvalue()
    return updated_zip_data


def regenerate_pdf_report(run_artifact: RunArtifact) -> bytes:
    """Updates the run artifact to include a regenerated pdf test procedure report.

    The pdf report is generated from `run_artifiact.reporting_data`, and replaces
    the existing pdf stored in the `run_artifact.file_data` zip.

    All other values (e.g. run_artifact_id remain unchanged).

    Args:
        run_artifact (RunArtifact): The RunArtifact to be updated. Note: this value is mutated.
    Returns:
        bytes: the updated zip file data.
    Raises:
        ValueError if regeneration of artifact fails for any reason.
    """
    if run_artifact.reporting_data is None:
        msg = "No reporting data found in run artifact."
        raise ValueError(f"Artifact regeneration error: {msg}")

    try:
        reporting_data: ReportingData = ReportingData.from_json(run_artifact.reporting_data)  # type: ignore
    except Exception as exc:
        msg = "Failed to convert json to ReportingData instance."
        logger.error(msg, exc_info=exc)
        raise ValueError(f"Artifact regeneration error: {msg}")

    msg = "Failed to generate pdf report from reporting data."
    try:
        pdf_data = generate_pdf_report_from_run_artifact(reporting_data=reporting_data)
    except Exception as exc:
        logger.error(msg, exc_info=exc)
        raise ValueError(f"Artifact regeneration error: {msg}")

    if not pdf_data:
        logger.error(msg)
        raise ValueError(f"Artifact regeneration error: {msg}")

    try:
        CACTUS_TEST_PROCEDURE_REPORT_PREFIX = "CactusTestProcedureReport"
        updated_zip_data = replace_pdf_in_zip_data(
            pdf_data=pdf_data, zip_data=run_artifact.file_data, pdf_filename_prefix=CACTUS_TEST_PROCEDURE_REPORT_PREFIX
        )
    except Exception as exc:
        msg = "Failed to replace pdf in archive."
        logger.error(msg, exc_info=exc)
        raise ValueError(f"Artifact regeneration error: {msg}")

    return updated_zip_data


async def regenerate_run_artifact(session: AsyncSession, run_artifact: RunArtifact) -> RunArtifact:
    """Regenerates the RunArtifact.

    - Uses the reporting data to (re)generate the run report.
    - Replaces the run report in the file data of `run_artifact`.
    - Updates the run artifact in the orchestrator database (to reflect the new file data).
    - Adds an entry to the RunReportGeneration table to record the fact the report was regenerated.

    Args:
        session: A database session.
        run_artifact (RunArtifact): The RunArtifact to update.
    Returns:
        RunArtifact: the updated RunArtifact
    Raises:
        ValueError: if regeneration of pdf report fails
    """

    updated_zip_data = regenerate_pdf_report(run_artifact=run_artifact)

    # Update the file data
    await update_runartifact_with_file_data(session=session, run_artifact=run_artifact, file_data=updated_zip_data)

    # Record the successful regeneration
    await create_run_report_generation_record(session=session, run_artifact_id=run_artifact.run_artifact_id)

    return run_artifact
