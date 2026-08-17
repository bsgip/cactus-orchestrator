import io
import logging
import random
import string
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import NewType

RunPath = NewType("RunPath", Path)
CompliancePath = NewType("CompliancePath", Path)

RANDOM_CHARS = string.ascii_letters + string.digits
RANDOM = random.SystemRandom()

REPORT_FILE_NAME = "CactusTestProcedureReport.pdf"
ERROR_FILE_NAME = "error.txt"

logger = logging.getLogger(__name__)


def run_directory(file_store_path: Path, run_id: int) -> RunPath:
    return RunPath(file_store_path / "runs" / f"run-{run_id}")


def compliance_directory(file_store_path: Path, compliance_request_finalisation_id: int) -> CompliancePath:
    return CompliancePath(file_store_path / "compliance" / f"finalisation-{compliance_request_finalisation_id}")


def run_finalise_directory(run_path: RunPath) -> Path:
    return run_path / "finalise"


def run_reports_directory(run_path: RunPath) -> Path:
    return run_path / "reports"


def timestamp_random_file_name(prefix: str, suffix: str) -> str:
    timestamp_us = int(datetime.now(UTC).timestamp() * 1000)
    rand_slug = RANDOM.choices(RANDOM_CHARS, k=6)  # add a random slug in case of timestamp collision

    return f"{prefix}_{timestamp_us}_{rand_slug}{suffix}"


def save_run_finalisation(file_store_path: Path, run_id: int, finalisation_zip_data: bytes) -> None:
    """Creates a finalise directory under the specified run_id directory. If this is called multiple times, the results
    will merge with the latest dump overwriting any conflicting files"""
    finalise_dir = run_finalise_directory(run_directory(file_store_path, run_id))

    logger.info(f"Persisting {len(finalisation_zip_data)} zip bytes to {finalise_dir}")
    finalise_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(io.BytesIO(finalisation_zip_data)) as zf:
        # Note - this is fine as we generate the ZIP direct from runner without passing it through the user
        # but if this was under the control of an external - we would need to do a lot more sanitation here
        zf.extractall(finalise_dir)


def save_run_report(file_store_path: Path, run_id: int, pdf_data: bytes) -> None:
    """Creates a reports directory under the specified run_id directory. The resulting file will ordered with a
    timestamp"""
    report_dir = run_reports_directory(run_directory(file_store_path, run_id))
    report_dir.mkdir(parents=True, exist_ok=True)

    report_file = report_dir / timestamp_random_file_name("CactusTestProcedureReport", ".pdf")

    logger.info(f"Persisting {len(pdf_data)} PDF bytes to {report_file}")
    with open(report_file, "wb") as fp:
        fp.write(pdf_data)


def _error_txt(*error_sources: list[str] | None) -> str | None:
    return "\n".join(error for es in error_sources if es is not None for error in es)


def fetch_run_zip(file_store_path: Path, run_id: int, error_info: list[str] | None = None) -> bytes:
    """Recreates a ZIP file containing runner finalisation data AND the latest report PDF. Can also include error data
    which will create a top level"""
    run_dir = run_directory(file_store_path, run_id)
    finalise_dir = run_finalise_directory(run_dir)
    reports_dir = run_reports_directory(run_dir)
    internal_zip_errors: list[str] = []

    report_pdf_path: Path | None = None
    if reports_dir.exists():
        all_reports = sorted((p for p in reports_dir.iterdir() if p.is_file()), key=lambda p: p.name, reverse=True)
        if len(all_reports) == 0:
            internal_zip_errors.append(f"No report PDF on record for run {run_id} (none found)")
        elif all_reports[0].is_file():
            report_pdf_path = all_reports[0]
        else:
            internal_zip_errors.append(f"No report PDF on record for run {run_id} (invalid file)")
    else:
        internal_zip_errors.append(f"No runner finalization data on record for run {run_id} (missing)")

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        # Add everything from finalise_dir, preserving relative paths
        if finalise_dir.exists() and finalise_dir.is_dir():
            for file_path in finalise_dir.rglob("*"):
                if file_path.is_file():
                    zip_archive_name = file_path.relative_to(finalise_dir)
                    zf.write(file_path, zip_archive_name)
        else:
            internal_zip_errors.append(f"No finalisation data for run {run_id}")

        # Add the latest report file
        if report_pdf_path is not None:
            zf.write(report_pdf_path, REPORT_FILE_NAME)

        # Add any errors that may have occurred around this generation
        error_text = _error_txt(internal_zip_errors, error_info)
        if error_text:
            zf.writestr(ERROR_FILE_NAME, data=error_text)

    return zip_buffer.getvalue()


def run_zip_exists(file_store_path: Path, run_id: int) -> bool:
    """True if there are on disk contents for the run with the specified ID"""
    run_dir = run_directory(file_store_path, run_id)
    finalise_dir = run_finalise_directory(run_dir)
    reports_dir = run_reports_directory(run_dir)
    return finalise_dir.exists() or reports_dir.exists()
