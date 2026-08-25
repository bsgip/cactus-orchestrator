import io
import logging
import random
import string
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import NewType

# We use these types to avoid accidently using the wrong path in the wrong function
RunPath = NewType("RunPath", Path)
CompliancePath = NewType("CompliancePath", Path)

RANDOM_CHARS = string.ascii_letters + string.digits
RANDOM = random.SystemRandom()

REPORT_FILE_NAME = "CactusTestProcedureReport.pdf"
ERROR_FILE_NAME = "error.txt"

logger = logging.getLogger(__name__)


def intermediate_dir(id: int, digits: int = 3) -> str:
    """Used for segmenting a LOT of sub dirs into smaller "chunks" to avoid having a single dir with a bajillion
    subdirs. This can cause problems under certain file formats

    eg: instead of
    /root/run-1234
    /root/run-1235
    /root/run-9999

    have:
    /root/234/run-1234
    /root/235/run-1235
    /root/234/run-9234
    """
    remainder = id % pow(10, digits)
    return f"{remainder:0{digits}}"


def run_directory(file_store_path: Path, run_id: int) -> RunPath:
    return RunPath(file_store_path / "runs" / intermediate_dir(run_id) / f"run-{run_id}")


def compliance_directory(file_store_path: Path, compliance_request_finalisation_id: int) -> CompliancePath:
    return CompliancePath(
        file_store_path
        / "compliance"
        / intermediate_dir(compliance_request_finalisation_id)
        / f"finalisation-{compliance_request_finalisation_id}"
    )


def run_finalise_directory(run_path: RunPath) -> Path:
    return run_path / "finalise"


def run_reports_directory(run_path: RunPath) -> Path:
    return run_path / "reports"


def timestamp_random_file_name(prefix: str, suffix: str) -> str:
    timestamp_us = int(datetime.now(UTC).timestamp() * 1000)
    rand_slug = "".join(RANDOM.choices(RANDOM_CHARS, k=6))  # add a random slug in case of timestamp collision

    return f"{prefix}_{timestamp_us}_{rand_slug}{suffix}"


def save_run_finalisation(file_store_path: Path, run_id: int, finalisation_zip_data: bytes) -> None:
    """Creates a finalise directory under the specified run_id directory. If this is called multiple times, the results
    will merge with the latest dump overwriting any conflicting files"""
    finalise_dir = run_finalise_directory(run_directory(file_store_path, run_id))

    logger.debug(f"Persisting {len(finalisation_zip_data)} zip bytes to {finalise_dir}")
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

    logger.debug(f"Persisting {len(pdf_data)} PDF bytes to {report_file}")
    with open(report_file, "wb") as fp:
        fp.write(pdf_data)


def _error_txt(*error_sources: list[str] | None) -> str | None:
    return "\n".join(error for es in error_sources if es is not None for error in es)


def _fetch_latest_file(dir: Path) -> Path | None:
    """Given a directory - return the 'latest' file as defined by file name NOT creation/modified time - This will
    ensure that a dir filled with timestamp_random_file_name files"""
    if not dir.exists() or not dir.is_dir():
        return None

    all_files = sorted((p for p in dir.iterdir() if p.is_file()), key=lambda p: p.name, reverse=True)
    if len(all_files) == 0:
        logger.info(f"No files in dir {dir} (none found)")
        return None
    else:
        return all_files[0]


def list_run_finalised_files(file_store_path: Path, run_id: int, filter: str | None = None) -> list[Path]:
    """Lists all finalisation files for a specific run id, optionally matching filter

    filter: The glob expression to filter files by."""

    run_dir = run_directory(file_store_path, run_id)
    finalise_dir = run_finalise_directory(run_dir).resolve()
    if not finalise_dir.exists() or not finalise_dir.is_dir():
        return []

    return [
        file_path.relative_to(finalise_dir)
        for file_path in finalise_dir.rglob(pattern=filter if filter else "*")
        if file_path.is_file()
    ]


def fetch_run_finalised_file(file_store_path: Path, run_id: int, file_name: Path | str) -> bytes | None:
    """Reads a specific file from the finalised files for a run_id - returns None if the file DNE / cannot be opened"""
    run_dir = run_directory(file_store_path, run_id)
    finalise_dir = run_finalise_directory(run_dir).resolve()

    target_path = (finalise_dir / file_name).resolve()
    if not target_path.is_relative_to(finalise_dir):
        raise ValueError(f"Supplied {file_name=} does NOT end up relative to {finalise_dir=}")

    try:
        with open(target_path, "rb") as fp:
            return fp.read()
    except Exception as exc:
        logger.error(f"Error reading {target_path=} for {run_id=}", exc_info=exc)
        return None


def fetch_run_zip(file_store_path: Path, run_id: int, error_info: list[str] | None = None) -> bytes:
    """Recreates a ZIP file containing runner finalisation data AND the latest report PDF. Can also include error data
    which will create a top level"""
    run_dir = run_directory(file_store_path, run_id)
    finalise_dir = run_finalise_directory(run_dir)
    reports_dir = run_reports_directory(run_dir)
    internal_zip_errors: list[str] = []
    report_pdf_path: Path | None = _fetch_latest_file(reports_dir)

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
        if report_pdf_path is None:
            internal_zip_errors.append(f"No report PDF on record for run {run_id}.")
        else:
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


def run_report_exists(file_store_path: Path, run_id: int) -> bool:
    """True if there is a report in the store for the specified run"""
    run_dir = run_directory(file_store_path, run_id)
    reports_dir = run_reports_directory(run_dir)

    return _fetch_latest_file(reports_dir) is not None


def save_compliance_finalisation_report(
    file_store_path: Path, compliance_request_finalisation_id: int, pdf_data: bytes
) -> None:
    """Creates a compliance finalisation representing compliance_request_finalisation_id. The resulting file will
    tagged with a timestamp such that repeated calls to this function will generate new revisions"""
    compliance_dir = compliance_directory(file_store_path, compliance_request_finalisation_id)
    compliance_dir.mkdir(parents=True, exist_ok=True)

    report_file = compliance_dir / timestamp_random_file_name("compliance", ".pdf")

    logger.debug(f"Persisting {len(pdf_data)} compliance PDF bytes to {report_file}")
    with open(report_file, "wb") as fp:
        fp.write(pdf_data)


def fetch_compliance_finalisation_report(
    file_store_path: Path, compliance_request_finalisation_id: int
) -> bytes | None:
    """Fetches the bytes from the most recent call to save_compliance_finalisation_report for the specified id. Returns
    None if there is no most recent call / data is missing."""
    compliance_dir = compliance_directory(file_store_path, compliance_request_finalisation_id)

    report_file = _fetch_latest_file(compliance_dir)
    if report_file is None:
        return None

    with open(report_file, "rb") as fp:
        return fp.read()


def compliance_finalisation_report_exists(file_store_path: Path, compliance_request_finalisation_id: int) -> bool:
    """True if there are on disk contents for the compliance finalisation report with the specified ID"""
    compliance_dir = compliance_directory(file_store_path, compliance_request_finalisation_id)
    return _fetch_latest_file(compliance_dir) is not None
