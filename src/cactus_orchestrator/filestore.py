import fcntl
import io
import logging
import os
import posixpath
import random
import shutil
import string
import zipfile
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import NewType

# We use these types to avoid accidently using the wrong path in the wrong function
RunPath = NewType("RunPath", Path)
CompliancePath = NewType("CompliancePath", Path)

RANDOM_CHARS = string.ascii_letters + string.digits
RANDOM = random.SystemRandom()

REPORT_FILE_NAME = "CactusTestProcedureReport.pdf"
ERROR_FILE_NAME = "error.txt"

# Runner finalisation data is stored as a single archive (to avoid exhausting inodes)
FINALISE_ZIP_NAME = "finalise.zip"
LEGACY_FINALISE_DIR_NAME = "finalise"  # Legacy format - each finalisation file extracted to disk
LEGACY_DELETING_DIR_NAME = "finalise.deleting"  # A legacy dir that is in the process of being removed
TMP_FILE_SUFFIX = ".tmp"

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
    """LEGACY - the directory that finalisation data was extracted into prior to being stored as a single zip"""
    return run_path / LEGACY_FINALISE_DIR_NAME


def run_finalise_zip(run_path: RunPath) -> Path:
    return run_path / FINALISE_ZIP_NAME


def run_reports_directory(run_path: RunPath) -> Path:
    return run_path / "reports"


def timestamp_random_file_name(prefix: str, suffix: str) -> str:
    timestamp_us = int(datetime.now(UTC).timestamp() * 1000)
    rand_slug = "".join(RANDOM.choices(RANDOM_CHARS, k=6))  # add a random slug in case of timestamp collision

    return f"{prefix}_{timestamp_us}_{rand_slug}{suffix}"


@contextmanager
def _run_lock(run_path: RunPath) -> Generator[None]:
    """Exclusive (cross process) lock over a run directory - used to serialise writers of the finalisation data.
    Readers do NOT need to take this lock as all writes are atomic."""
    fd = os.open(run_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)  # Releases the flock


def _fsync_dir(dir: Path) -> None:
    fd = os.open(dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write(target: Path, data: bytes) -> None:
    """Writes data to target such that target will either contain the old contents or the full new contents (never a
    partial write) - even if the process / machine crashes."""
    tmp = target.with_name(target.name + TMP_FILE_SUFFIX)
    with open(tmp, "wb") as fp:
        fp.write(data)
        fp.flush()
        os.fsync(fp.fileno())
    os.replace(tmp, target)
    _fsync_dir(target.parent)


def _normalise_member_name(name: str) -> str | None:
    """Normalises a ZIP member name to the relative path it would have been extracted to (mirroring the sanitisation
    performed by ZipFile.extractall). Returns None for directory entries / names that don't map to a file"""
    if name.endswith("/"):
        return None
    parts = [p for p in name.split("/") if p not in ("", ".", "..")]
    if not parts:
        return None
    return "/".join(parts)


def _zip_members(zf: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    """Returns the file members of zf keyed by their normalised name. Later duplicates take precedence (as they would
    have with extractall)"""
    members: dict[str, zipfile.ZipInfo] = {}
    for info in zf.infolist():
        name = _normalise_member_name(info.filename)
        if name is not None:
            members[name] = info
    return members


def _legacy_files(legacy_dir: Path) -> dict[str, Path]:
    """Returns all files under legacy_dir keyed by their relative posix path"""
    return {p.relative_to(legacy_dir).as_posix(): p for p in sorted(legacy_dir.rglob("*")) if p.is_file()}


def save_run_finalisation(file_store_path: Path, run_id: int, finalisation_zip_data: bytes) -> None:
    """Persists the runner finalisation ZIP for the specified run_id. If this is called multiple times, the results
    will merge with the latest dump overwriting any conflicting files.

    The data is stored as a single ZIP file (verbatim where possible). If there is legacy (extracted) finalisation
    data for this run, it will be merged into the ZIP and the legacy data removed."""
    run_dir = run_directory(file_store_path, run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    zip_path = run_finalise_zip(run_dir)
    legacy_dir = run_finalise_directory(run_dir)

    logger.debug(f"Persisting {len(finalisation_zip_data)} zip bytes to {zip_path}")
    with zipfile.ZipFile(io.BytesIO(finalisation_zip_data)) as new_zf:
        bad_member = new_zf.testzip()
        if bad_member is not None:
            raise ValueError(f"Finalisation ZIP for run {run_id} has a corrupt member {bad_member}")

        with _run_lock(run_dir):
            has_legacy = legacy_dir.is_dir()
            has_existing = zip_path.is_file()
            is_normalised = all(_normalise_member_name(i.filename) in (i.filename, None) for i in new_zf.infolist())

            if not has_legacy and not has_existing and is_normalised:
                # The simple case - store the data exactly as it was received
                _atomic_write(zip_path, finalisation_zip_data)
                return

            # Otherwise we need to merge everything together: legacy < existing zip < new zip
            merged_data = _merge_finalisation(
                new_zf, zip_path if has_existing else None, legacy_dir if has_legacy else None
            )
            _atomic_write(zip_path, merged_data)

            if has_legacy:
                # The legacy data is now fully captured in the zip - it can be removed
                deleting_dir = run_dir / LEGACY_DELETING_DIR_NAME
                if deleting_dir.exists():
                    shutil.rmtree(deleting_dir)
                os.rename(legacy_dir, deleting_dir)
                shutil.rmtree(deleting_dir)


def _merge_finalisation(new_zf: zipfile.ZipFile, existing_zip: Path | None, legacy_dir: Path | None) -> bytes:
    """Generates a new ZIP from the merging of (in order of increasing precedence) legacy_dir, existing_zip, new_zf"""
    merged_buffer = io.BytesIO()
    with zipfile.ZipFile(merged_buffer, "w", zipfile.ZIP_DEFLATED, strict_timestamps=False) as out_zf:
        new_members = _zip_members(new_zf)
        existing_members: dict[str, zipfile.ZipInfo] = {}
        if existing_zip is not None:
            with zipfile.ZipFile(existing_zip) as existing_zf:
                existing_members = _zip_members(existing_zf)
                for name, info in existing_members.items():
                    if name not in new_members:
                        out_zf.writestr(_copy_info(name, info), existing_zf.read(info))
        if legacy_dir is not None:
            for name, file_path in _legacy_files(legacy_dir).items():
                if name not in new_members and name not in existing_members:
                    out_zf.write(file_path, name)
        for name, info in new_members.items():
            out_zf.writestr(_copy_info(name, info), new_zf.read(info))
    return merged_buffer.getvalue()


def _copy_info(name: str, info: zipfile.ZipInfo) -> zipfile.ZipInfo:
    new_info = zipfile.ZipInfo(name, date_time=info.date_time)
    new_info.compress_type = zipfile.ZIP_DEFLATED
    new_info.external_attr = info.external_attr
    return new_info


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

    filter: The glob expression to filter files by (matched against the end of the file's relative path)."""

    run_dir = run_directory(file_store_path, run_id)
    zip_path = run_finalise_zip(run_dir)
    if zip_path.is_file():
        with zipfile.ZipFile(zip_path) as zf:
            names = sorted(_zip_members(zf).keys())
        return [Path(n) for n in names if filter is None or PurePosixPath(n).match(filter)]

    # LEGACY - fallback to extracted data
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

    zip_path = run_finalise_zip(run_dir)
    if zip_path.is_file():
        member_name = posixpath.normpath(target_path.relative_to(finalise_dir).as_posix())
        try:
            with zipfile.ZipFile(zip_path) as zf:
                info = _zip_members(zf).get(member_name, None)
                if info is None:
                    return None
                return zf.read(info)
        except Exception as exc:
            logger.error(f"Error reading {member_name=} from {zip_path=} for {run_id=}", exc_info=exc)
            return None

    # LEGACY - fallback to extracted data
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
    zip_path = run_finalise_zip(run_dir)
    finalise_dir = run_finalise_directory(run_dir)
    reports_dir = run_reports_directory(run_dir)
    internal_zip_errors: list[str] = []
    report_pdf_path: Path | None = _fetch_latest_file(reports_dir)

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED, strict_timestamps=False) as zf:
        # Add everything from the finalisation data, preserving relative paths
        if zip_path.is_file():
            with zipfile.ZipFile(zip_path) as finalise_zf:
                for name, info in _zip_members(finalise_zf).items():
                    zf.writestr(_copy_info(name, info), finalise_zf.read(info))
        elif finalise_dir.exists() and finalise_dir.is_dir():
            # LEGACY - fallback to extracted data
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
    zip_path = run_finalise_zip(run_dir)
    finalise_dir = run_finalise_directory(run_dir)
    reports_dir = run_reports_directory(run_dir)
    return zip_path.exists() or finalise_dir.exists() or reports_dir.exists()


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
