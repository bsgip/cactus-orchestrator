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
from cactus_orchestrator.reporting.generate import generate_pdf_report_v1

logger = logging.getLogger(__name__)

PDF_GENERATION_ERRORS_FILE_NAME = "pdf-generation-errors.txt"


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


async def regenerate_pdf_report(file_data: bytes, raw_reporting_data: str, version: int) -> bytes:
    """A pdf run report is generated from `reporting_data`, and replaces the existing
    pdf stored in the `file_data` zip.

    All other files in the file_data zip archive remain unchanged.

    On PDF generation failure, a pdf-generation-errors.txt file is written into the zip
    and the updated zip is returned (rather than raising), so the error is visible on download.

    Args:
        file_data (bytes): a zip archive containing a pdf run report (to be replaced)
        raw_reporting_data (str): ReportingData as a json encoded string
        version (int): the version of the reporting data in `raw_reporting_data`.
    Returns:
        bytes: the updated zip file data.
    Raises:
        ValueError if the reporting data cannot be parsed or the zip cannot be written.
    """
    try:
        reporting_data = ReportingData.from_json(version, raw_reporting_data)  # type: ignore
    except Exception as exc:
        msg = "Failed to convert json to ReportingData instance."
        logger.error(msg, exc_info=exc)
        raise ValueError(f"Artifact regeneration error: {msg}") from exc

    pdf_generation_error: str | None = None
    pdf_data: bytes | None = None

    try:
        if version == 1:
            pdf_data = await generate_pdf_report_v1(reporting_data=reporting_data)
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

    updated_zip_data = await regenerate_pdf_report(
        file_data=run_artifact.file_data, raw_reporting_data=run_artifact.reporting_data, version=run_artifact.version
    )

    # Update the file data
    await update_runartifact_with_file_data(session=session, run_artifact=run_artifact, file_data=updated_zip_data)

    # Record the successful regeneration
    await create_run_report_generation_record(session=session, run_artifact_id=run_artifact.run_artifact_id)

    return run_artifact
