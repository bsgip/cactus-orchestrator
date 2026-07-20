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

PDF_GENERATION_ERRORS_FILE_NAME = "pdf-generation-errors.txt"


@dataclass
class Artifact:
    file_data: bytes
    mime_type: str


async def generate_compliance_artifact(
    requester: User,
    compliance_request: ComplianceRequest,
) -> Artifact:

    compliance_classes, excluded_classes, class_to_test_procedures, compliance_runs = determine_compliance(
        compliance_request=compliance_request
    )

    file_data = pdf_report_as_bytes(
        requester=requester,
        user=compliance_request.created_by_user,
        request_id=f"{compliance_request.compliance_request_id}",
        csip_aus_version=compliance_request.csip_aus_version,
        finalisation_datetime=datetime.now(UTC),
        compliance_id=compliance_request.compliance_request_id,
        compliance_classes=compliance_classes,
        excluded_compliance_classes=excluded_classes,
        class_to_test_procedures=class_to_test_procedures,
        compliance_runs=compliance_runs,
    )

    return Artifact(file_data=file_data, mime_type="application/pdf")


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
    file_data = deprecated_pdf_report_as_bytes(
        requester=requester,
        user=user,
        name=run_group.name,
        name_id=f"{run_group.run_group_id}",
        name_type="Run Group",
        csip_aus_version=run_group.csip_aus_version,
        finalisation_datetime=compliance_record.created_at,
        compliance_id=compliance_record.compliance_record_id,
        compliance_by_class=compliance_by_class,
    )

    if file_data is None:
        return None
    return Artifact(file_data=file_data, mime_type="application/pdf")


async def replace_pdf_in_zip_data(pdf_data: bytes, zip_data: bytes, pdf_filename_prefix: str) -> bytes:
    """Replaces existing PDFs in `zip_data` with `pdf_data`, or adds the PDF if none is present.

    Any file whose name starts with `pdf_filename_prefix` and ends with `.pdf` is replaced.
    If no such file exists (e.g. the runner no longer generates a PDF), the PDF is added as
    `{pdf_filename_prefix}.pdf`.

    Args:
        pdf_data (bytes): the pdf data to inject
        zip_data (bytes): a zip file as bytes
        pdf_filename_prefix: prefix used to identify existing pdf files to replace

    Returns:
        bytes: a zip file as bytes with the pdf injected or replaced
    """

    zip_buffer = io.BytesIO()
    pdf_was_written = False
    with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as updated_zip:
        with zipfile.ZipFile(io.BytesIO(zip_data)) as original_zip:
            for member in original_zip.namelist():
                with updated_zip.open(member, "w") as member_handle:
                    if member.startswith(pdf_filename_prefix) and member.endswith("pdf"):
                        member_handle.write(pdf_data)
                        pdf_was_written = True
                    else:
                        member_handle.write(original_zip.read(member))

        if not pdf_was_written:
            with updated_zip.open(f"{pdf_filename_prefix}.pdf", "w") as member_handle:
                member_handle.write(pdf_data)

    updated_zip_data: bytes = zip_buffer.getvalue()
    return updated_zip_data


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


async def regenerate_pdf_report(
    file_data: bytes, raw_reporting_data: str, version: int, playlist_info: str | None = None
) -> bytes:
    """A pdf run report is generated from `reporting_data`, and replaces the existing
    pdf stored in the `file_data` zip.

    All other files in the file_data zip archive remain unchanged.

    On PDF generation failure, a pdf-generation-errors.txt file is written into the zip
    and the updated zip is returned (rather than raising), so the error is visible on download.

    Args:
        file_data (bytes): a zip archive containing a pdf run report (to be replaced)
        raw_reporting_data (str): ReportingData as a json encoded string
        version (int): the version of the reporting data in `raw_reporting_data`.
        playlist_info (str | None): "Test N of M" label for playlist runs, sourced from the orchestrator DB
            (RunnerState no longer carries playlist position).
    Returns:
        bytes: the updated zip file data.
    Raises:
        ValueError if the reporting data cannot be parsed or the zip cannot be written.
    """
    try:
        reporting_data = ReportingData.from_json(version, raw_reporting_data)
    except Exception as exc:
        msg = "Failed to convert json to ReportingData instance."
        logger.error(msg, exc_info=exc)
        raise ValueError(f"Artifact regeneration error: {msg}") from exc

    pdf_generation_error: str | None = None
    pdf_data: bytes | None = None

    try:
        if version == 1:
            pdf_data = await generate_pdf_report_v1(reporting_data=reporting_data, playlist_info=playlist_info)
        else:
            raise ValueError(f"Unknown version of reporting data ({version})")
    except Exception as exc:
        msg = "Failed to generate pdf report from reporting data."
        logger.error(msg, exc_info=exc)
        pdf_generation_error = f"{msg}\n{exc}"

    if pdf_data is None and pdf_generation_error is None:
        pdf_generation_error = "PDF generation returned no data."
        logger.error(pdf_generation_error)

    if pdf_generation_error is not None:
        return _add_text_file_to_zip_data(file_data, PDF_GENERATION_ERRORS_FILE_NAME, pdf_generation_error)

    if pdf_data is not None:
        try:
            cactus_test_procedure_report_prefix = "CactusTestProcedureReport"
            updated_zip_data = await replace_pdf_in_zip_data(
                pdf_data=pdf_data, zip_data=file_data, pdf_filename_prefix=cactus_test_procedure_report_prefix
            )
        except Exception as exc:
            msg = "Failed to replace pdf in archive."
            logger.error(msg, exc_info=exc)
            raise ValueError(f"Artifact regeneration error: {msg}") from exc

    return updated_zip_data


async def regenerate_run_artifact(session: AsyncSession, run: Run, run_artifact: RunArtifact) -> RunArtifact:
    """Regenerates the RunArtifact.

    - Uses the reporting data to (re)generate the run report.
    - Replaces the run report in the file data of `run_artifact`.
    - Updates the run artifact in the orchestrator database (to reflect the new file data).
    - Adds an entry to the RunReportGeneration table to record the fact the report was regenerated.

    Args:
        session: A database session.
        run (Run): The Run the artifact belongs to (used to source the playlist "Test N of M" label).
        run_artifact (RunArtifact): The RunArtifact to update.
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
    )

    # Update the file data
    await update_runartifact_with_file_data(session=session, run_artifact=run_artifact, file_data=updated_zip_data)

    # Record the successful regeneration
    await create_run_report_generation_record(session=session, run_artifact_id=run_artifact.run_artifact_id)

    return run_artifact
