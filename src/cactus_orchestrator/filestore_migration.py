#!/usr/bin/env python3
"""Migrates the orchestrator file store from the legacy layout (runner finalisation ZIPs extracted to disk - often
thousands of files per run) to the new layout (the finalisation data kept as a single ZIP file per run).

    runs/NNN/run-{id}/finalise/**   ->   runs/NNN/run-{id}/finalise.zip

This module is deliberately STANDALONE - it only uses the python (>= 3.12) standard library and does NOT import
anything from cactus_orchestrator. It can be run either:

    # From inside the running orchestrator container (uses FILE_STORE_PATH, runs as the same user as the app)
    podman exec -it <orchestrator-container> python -m cactus_orchestrator.filestore_migration --dry-run
    podman exec -it <orchestrator-container> python -m cactus_orchestrator.filestore_migration

    # Or copied anywhere and run with a vanilla python, eg:
    python3 filestore_migration.py /var/lib/cactus/filestore

It is safe to run against a LIVE file store (with the orchestrator still running) and it is safe to interrupt / kill /
crash at any point - simply rerun it and it will carry on where it left off. The file system itself is the only state.


For each run:
  1. (Convert) The legacy dir is written to finalise.zip.tmp, fsync'd and then verified (CRC check, exact member list
     and a SHA-256 of every member compared against the source files). Only then is it atomically renamed to
     finalise.zip. From this point, the orchestrator will read from finalise.zip instead of the legacy dir.
  2. (Delete) After --grace-seconds (to allow any in-flight orchestrator reads of the legacy dir to finish), the legacy
     dir is re-verified against finalise.zip (every legacy file must be in the zip with an identical SHA-256), renamed
     to finalise.deleting and then removed.

Exit codes: 0 = complete, 1 = one or more runs failed, 2 = bad arguments / already running, 3 = incomplete (stopped
early or legacy dirs still awaiting deletion) - rerun to finish.

Any run that fails will have a finalise.migration_failed marker written (describing the failure) and will be skipped
by subsequent invocations (unless --retry-failed is specified). Nothing is ever deleted from a failed run.

Writers of a run's finalisation data (this script AND the orchestrator) serialise via an exclusive flock on the
run directory. Only one instance of this script can run at a time (enforced via a lock file in the file store root).
"""

import argparse
import fcntl
import hashlib
import logging
import os
import shutil
import signal
import stat
import sys
import time
import zipfile
from collections import deque
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from types import FrameType
from typing import IO

# NOTE: These names MUST be kept in sync with cactus_orchestrator/filestore.py
FINALISE_ZIP_NAME = "finalise.zip"
LEGACY_FINALISE_DIR_NAME = "finalise"
LEGACY_DELETING_DIR_NAME = "finalise.deleting"
TMP_FILE_SUFFIX = ".tmp"
RUNS_DIR_NAME = "runs"
RUN_DIR_PREFIX = "run-"

FAILED_MARKER_NAME = "finalise.migration_failed"
MIGRATION_LOCK_NAME = ".filestore_migration.lock"

READ_CHUNK_BYTES = 1024 * 1024
ZIP64_THRESHOLD_BYTES = 0x7FFFFFFF
FREE_SPACE_MARGIN_BYTES = 64 * 1024 * 1024  # Always leave at least this much free disk space
FREE_INODES_MARGIN = 100  # Always leave at least this many free inodes

logger = logging.getLogger("filestore_migration")


class MigrationError(Exception):
    """A (per run) failure that should be recorded and require manual intervention"""


@dataclass
class Stats:
    started_at: float = field(default_factory=time.monotonic)
    to_convert: int = 0  # Runs (found during the survey) with a legacy dir and no zip
    to_delete: int = 0  # Runs (found during the survey) with BOTH a zip and a legacy dir
    previously_failed: int = 0  # Runs (found during the survey) with a failure marker
    processed: int = 0  # Runs (out of to_convert + to_delete) that have been visited
    converted: int = 0
    deleted: int = 0
    skipped: int = 0
    failed: int = 0
    files: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    failures: list[str] = field(default_factory=list)


@dataclass
class RunState:
    has_zip: bool
    has_legacy: bool
    has_deleting: bool
    has_failed_marker: bool


@dataclass(frozen=True)
class FileDigest:
    sha256: str
    size: int


class StopRequested:
    """Set by signal handlers - checked between runs so that an interrupt leaves things tidy (not that it's required
    for correctness)"""

    def __init__(self) -> None:
        self.stop = False

    def handler(self, signum: int, frame: FrameType | None) -> None:
        logger.warning(f"Received signal {signum} - will stop after the current run")
        self.stop = True


def run_state(run_dir: Path) -> RunState:
    return RunState(
        has_zip=(run_dir / FINALISE_ZIP_NAME).is_file(),
        has_legacy=(run_dir / LEGACY_FINALISE_DIR_NAME).is_dir(),
        has_deleting=(run_dir / LEGACY_DELETING_DIR_NAME).is_dir(),
        has_failed_marker=(run_dir / FAILED_MARKER_NAME).is_file(),
    )


def iter_run_dirs(file_store_path: Path) -> Iterator[Path]:
    """Yields every run-XXX directory in the file store (ordered by bucket, then run id)"""
    runs_root = file_store_path / RUNS_DIR_NAME
    if not runs_root.is_dir():
        return

    for bucket in sorted(e.path for e in os.scandir(runs_root) if e.is_dir(follow_symlinks=False)):
        run_dirs: list[tuple[int, str]] = []
        for entry in os.scandir(bucket):
            if not entry.name.startswith(RUN_DIR_PREFIX) or not entry.is_dir(follow_symlinks=False):
                continue
            try:
                run_dirs.append((int(entry.name[len(RUN_DIR_PREFIX) :]), entry.path))
            except ValueError:
                logger.warning(f"Ignoring unexpected directory {entry.path}")
        for _, path in sorted(run_dirs):
            yield Path(path)


@contextmanager
def run_lock(run_dir: Path) -> Generator[None]:
    """Exclusive lock over a run directory - the orchestrator takes the same lock when writing finalisation data"""
    fd = os.open(run_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def fsync_dir(dir: Path) -> None:
    fd = os.open(dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def collect_legacy_files(legacy_dir: Path) -> list[tuple[str, Path]]:
    """Lists every file under legacy_dir as (relative posix name, path). Raises MigrationError for anything that can't
    be faithfully represented in a ZIP (symlinks, devices, undecodable names)"""
    files: list[tuple[str, Path]] = []
    for dir_path, dir_names, file_names in os.walk(legacy_dir, followlinks=False):
        for name in dir_names + file_names:
            path = Path(dir_path) / name
            mode = path.lstat().st_mode
            rel_name = path.relative_to(legacy_dir).as_posix()
            try:
                rel_name.encode("utf-8")
            except UnicodeEncodeError:
                raise MigrationError(f"Undecodable file name {path!r}") from None
            if stat.S_ISLNK(mode):
                raise MigrationError(f"Symlink found at {path}")
            if stat.S_ISREG(mode):
                files.append((rel_name, path))
            elif not stat.S_ISDIR(mode):
                raise MigrationError(f"Unsupported file type at {path}")
    return sorted(files)


def digest_stream(chunks: Iterator[bytes]) -> FileDigest:
    h = hashlib.sha256()
    size = 0
    for chunk in chunks:
        h.update(chunk)
        size += len(chunk)
    return FileDigest(h.hexdigest(), size)


def iter_chunks(fp: IO[bytes]) -> Iterator[bytes]:
    while chunk := fp.read(READ_CHUNK_BYTES):
        yield chunk


def digest_file(path: Path) -> FileDigest:
    with open(path, "rb") as fp:
        return digest_stream(iter_chunks(fp))


def write_zip(files: list[tuple[str, Path]], tmp_path: Path) -> dict[str, FileDigest]:
    """Writes files to a new ZIP at tmp_path (fsync'd) - returns the digest of every file as it was read"""
    digests: dict[str, FileDigest] = {}
    with zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED, strict_timestamps=False) as zf:
        for name, path in files:
            info = zipfile.ZipInfo.from_file(path, name, strict_timestamps=False)
            info.compress_type = zipfile.ZIP_DEFLATED
            h = hashlib.sha256()
            size = 0
            with open(path, "rb") as src, zf.open(info, "w", force_zip64=info.file_size > ZIP64_THRESHOLD_BYTES) as dst:
                for chunk in iter_chunks(src):
                    h.update(chunk)
                    size += len(chunk)
                    dst.write(chunk)
            if size != info.file_size:
                raise MigrationError(f"{path} changed size while being read ({info.file_size} -> {size})")
            digests[name] = FileDigest(h.hexdigest(), size)

    with open(tmp_path, "rb") as fp:
        os.fsync(fp.fileno())
    return digests


def read_zip_digests(zip_path: Path) -> dict[str, FileDigest]:
    """CRC checks every member of zip_path and returns the digest of every (non directory) member"""
    with zipfile.ZipFile(zip_path) as zf:
        bad_member = zf.testzip()
        if bad_member is not None:
            raise MigrationError(f"{zip_path} failed CRC check on member {bad_member}")

        digests: dict[str, FileDigest] = {}
        for info in zf.infolist():
            if info.is_dir():
                continue
            if info.filename in digests:
                raise MigrationError(f"{zip_path} has duplicate member {info.filename}")
            with zf.open(info) as fp:
                digests[info.filename] = digest_stream(iter_chunks(fp))
        return digests


def verify_zip_exactly(zip_path: Path, expected: dict[str, FileDigest]) -> None:
    """Raises MigrationError if zip_path doesn't contain EXACTLY the expected members/contents"""
    actual = read_zip_digests(zip_path)
    if actual.keys() != expected.keys():
        missing = sorted(expected.keys() - actual.keys())[:5]
        extra = sorted(actual.keys() - expected.keys())[:5]
        raise MigrationError(f"{zip_path} member mismatch. Missing (first 5): {missing} Extra (first 5): {extra}")
    for name, digest in expected.items():
        if actual[name] != digest:
            raise MigrationError(f"{zip_path} member {name} has {actual[name]} but expected {digest}")


def verify_legacy_in_zip(legacy_dir: Path, zip_path: Path) -> None:
    """Raises MigrationError unless EVERY file in legacy_dir exists in zip_path with identical contents"""
    zip_digests = read_zip_digests(zip_path)
    for name, path in collect_legacy_files(legacy_dir):
        zip_digest = zip_digests.get(name, None)
        if zip_digest is None:
            raise MigrationError(f"{path} is NOT in {zip_path}")
        file_digest = digest_file(path)
        if file_digest != zip_digest:
            raise MigrationError(f"{path} has {file_digest} but {zip_path} has {zip_digest}")


def check_free_space(dir: Path, required_bytes: int) -> None:
    free_bytes = shutil.disk_usage(dir).free
    if free_bytes - required_bytes < FREE_SPACE_MARGIN_BYTES:
        raise MigrationError(f"Insufficient disk space: {free_bytes} free but need {required_bytes} + margin")
    vfs = os.statvfs(dir)
    if vfs.f_files > 0 and vfs.f_favail < FREE_INODES_MARGIN:
        raise MigrationError(f"Insufficient free inodes: {vfs.f_favail} available")


def convert_run(run_dir: Path, stats: Stats) -> bool:
    """Converts the legacy dir (if any) of run_dir into a verified finalise.zip. Returns True if a conversion took
    place. Must be called with the run lock held."""
    legacy_dir = run_dir / LEGACY_FINALISE_DIR_NAME
    zip_path = run_dir / FINALISE_ZIP_NAME
    tmp_path = run_dir / (FINALISE_ZIP_NAME + TMP_FILE_SUFFIX)

    state = run_state(run_dir)
    if state.has_zip or not state.has_legacy:
        return False  # Nothing to convert (we hold the lock so this can't change underneath us)

    files = collect_legacy_files(legacy_dir)
    total_bytes = sum(p.stat().st_size for _, p in files)
    check_free_space(run_dir, total_bytes)

    try:
        tmp_path.unlink(missing_ok=True)  # Cleanup from any previous crash
        digests = write_zip(files, tmp_path)
        verify_zip_exactly(tmp_path, digests)
        bytes_out = tmp_path.stat().st_size
        os.replace(tmp_path, zip_path)
        fsync_dir(run_dir)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise

    stats.converted += 1
    stats.files += len(files)
    stats.bytes_in += total_bytes
    stats.bytes_out += bytes_out
    return True


def delete_legacy(run_dir: Path) -> bool:
    """Removes the legacy dir (if any) of run_dir after verifying it's entirely contained within finalise.zip. Returns
    True if anything was removed. Must be called with the run lock held."""
    legacy_dir = run_dir / LEGACY_FINALISE_DIR_NAME
    deleting_dir = run_dir / LEGACY_DELETING_DIR_NAME
    zip_path = run_dir / FINALISE_ZIP_NAME

    state = run_state(run_dir)
    if not state.has_zip:
        if state.has_deleting:
            raise MigrationError(f"{deleting_dir} exists without a {FINALISE_ZIP_NAME} - refusing to delete")
        return False

    if state.has_legacy:
        verify_legacy_in_zip(legacy_dir, zip_path)
        if state.has_deleting:
            # Only possible with a previous crash mid delete - this was ALREADY verified before it was renamed
            shutil.rmtree(deleting_dir)
        os.rename(legacy_dir, deleting_dir)
        fsync_dir(run_dir)

    if state.has_legacy or state.has_deleting:
        shutil.rmtree(deleting_dir)
        return True
    return False


def record_failure(run_dir: Path, exc: BaseException, stats: Stats, dry_run: bool) -> None:
    stats.failed += 1
    message = f"{type(exc).__name__}: {exc}"
    stats.failures.append(f"{run_dir}: {message}")
    logger.error(f"FAILED {run_dir}: {message}", exc_info=not isinstance(exc, MigrationError))
    if dry_run:
        return
    try:
        with open(run_dir / FAILED_MARKER_NAME, "w") as fp:
            fp.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} {message}\n")
    except Exception as marker_exc:
        logger.error(f"Unable to write failure marker for {run_dir}: {marker_exc}")


def format_bytes(n: float) -> str:
    for unit in ["B", "KiB", "MiB", "GiB"]:
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


def format_duration(seconds: float) -> str:
    seconds = int(seconds)
    return f"{seconds // 3600}h{(seconds % 3600) // 60:02}m{seconds % 60:02}s"


def report_progress(stats: Stats, pending_deletes: int, prefix: str = "PROGRESS") -> None:
    total = stats.to_convert + stats.to_delete
    elapsed = time.monotonic() - stats.started_at
    rate = stats.processed / elapsed if elapsed > 0 else 0.0
    eta = format_duration((total - stats.processed) / rate) if rate > 0 else "unknown"
    pct = (100.0 * stats.processed / total) if total else 100.0
    logger.info(
        f"{prefix}: {stats.processed:,}/{total:,} runs ({pct:.1f}%) | converted={stats.converted:,} "
        f"deleted={stats.deleted:,} skipped={stats.skipped:,} failed={stats.failed:,} "
        f"pending_delete={pending_deletes:,} | files={stats.files:,} "
        f"{format_bytes(stats.bytes_in)} -> {format_bytes(stats.bytes_out)} | "
        f"{rate:.2f} runs/s elapsed={format_duration(elapsed)} eta={eta}"
    )


@dataclass
class Survey:
    convert: list[Path] = field(default_factory=list)
    delete: list[Path] = field(default_factory=list)


def survey(file_store_path: Path, stats: Stats, retry_failed: bool, progress_seconds: float) -> Survey:
    """Enumerates every run directory and works out what needs doing"""
    result = Survey()
    last_report = time.monotonic()
    seen = 0
    for run_dir in iter_run_dirs(file_store_path):
        seen += 1
        state = run_state(run_dir)
        if state.has_failed_marker:
            stats.previously_failed += 1
            if not retry_failed:
                continue
        if state.has_legacy and not state.has_zip:
            result.convert.append(run_dir)
        elif state.has_zip and (state.has_legacy or state.has_deleting):
            result.delete.append(run_dir)
        elif state.has_deleting:
            result.delete.append(run_dir)  # This will be flagged as a failure

        if time.monotonic() - last_report > progress_seconds:
            last_report = time.monotonic()
            logger.info(f"SURVEY: {seen:,} run dirs scanned so far...")

    stats.to_convert = len(result.convert)
    stats.to_delete = len(result.delete)
    logger.info(
        f"SURVEY COMPLETE: {seen:,} run dirs. {stats.to_convert:,} to convert, {stats.to_delete:,} with legacy data "
        f"awaiting deletion, {stats.previously_failed:,} with a {FAILED_MARKER_NAME} marker"
        + (" (will be retried)" if retry_failed else " (will be skipped)")
    )
    return result


def dry_run_check(run_dir: Path, stats: Stats) -> None:
    """Checks a legacy dir can be enumerated/converted without writing anything"""
    files = collect_legacy_files(run_dir / LEGACY_FINALISE_DIR_NAME)
    stats.files += len(files)
    stats.bytes_in += sum(p.stat().st_size for _, p in files)
    stats.converted += 1


class Migrator:
    def __init__(self, args: argparse.Namespace, stats: Stats, stop: StopRequested) -> None:
        self.args = args
        self.stats = stats
        self.stop = stop
        self.pending: deque[tuple[float, Path]] = deque()  # (delete_due_at, run_dir) - ordered by delete_due_at
        self.last_report = time.monotonic()

    def maybe_report(self, force: bool = False) -> None:
        if force or time.monotonic() - self.last_report >= self.args.progress_seconds:
            self.last_report = time.monotonic()
            report_progress(self.stats, len(self.pending))

    def queue_delete(self, run_dir: Path) -> None:
        if self.args.keep_legacy:
            return
        try:
            zip_mtime = (run_dir / FINALISE_ZIP_NAME).stat().st_mtime
        except FileNotFoundError:
            zip_mtime = time.time()
        self.pending.append((zip_mtime + self.args.grace_seconds, run_dir))

    def process_due_deletes(self, wait: bool) -> None:
        """Deletes legacy data for queued runs whose grace period has elapsed. If wait - blocks until queue empty"""
        while self.pending and not self.stop.stop:
            due_at, run_dir = self.pending[0]
            remaining = due_at - time.time()
            if remaining > 0:
                if not wait:
                    return
                time.sleep(min(remaining, 1.0))
                self.maybe_report()
                continue

            self.pending.popleft()
            try:
                with run_lock(run_dir):
                    if delete_legacy(run_dir):
                        self.stats.deleted += 1
            except Exception as exc:
                record_failure(run_dir, exc, self.stats, dry_run=False)
            self.maybe_report()

    def handle_run(self, run_dir: Path, convert: bool) -> None:
        state = run_state(run_dir)
        if state.has_failed_marker and not self.args.retry_failed:
            self.stats.skipped += 1
            return

        if self.args.dry_run:
            if convert:
                dry_run_check(run_dir, self.stats)
            return

        if convert:
            with run_lock(run_dir):
                converted = convert_run(run_dir, self.stats)
            if converted:
                logger.debug(f"Converted {run_dir}")
            else:
                self.stats.skipped += 1  # Someone else got there first
        (run_dir / FAILED_MARKER_NAME).unlink(missing_ok=True)  # Only reached on success (relevant for retries)
        self.queue_delete(run_dir)

    def run(self, work: Survey) -> None:
        items = [(p, True) for p in work.convert] + [(p, False) for p in work.delete]
        for i, (run_dir, convert) in enumerate(items):
            if self.stop.stop or (self.args.limit is not None and i >= self.args.limit):
                break
            try:
                self.handle_run(run_dir, convert)
            except Exception as exc:
                record_failure(run_dir, exc, self.stats, self.args.dry_run)
            self.stats.processed += 1

            self.process_due_deletes(wait=False)
            self.maybe_report()
            if self.args.sleep_seconds > 0:
                time.sleep(self.args.sleep_seconds)

        if self.pending and not self.stop.stop:
            logger.info(f"Waiting for the grace period to elapse on {len(self.pending):,} legacy dirs...")
        self.process_due_deletes(wait=True)


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "file_store_path",
        nargs="?",
        default=os.environ.get("FILE_STORE_PATH"),
        help="Root of the orchestrator file store. Defaults to the FILE_STORE_PATH environment variable.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Survey and check legacy dirs, but write NOTHING.")
    parser.add_argument(
        "--keep-legacy", action="store_true", help="Convert to finalise.zip but do NOT delete the legacy dirs."
    )
    parser.add_argument(
        "--grace-seconds",
        type=float,
        default=120.0,
        help="Minimum age of a finalise.zip before its legacy dir is deleted (allows in-flight reads to finish).",
    )
    parser.add_argument("--progress-seconds", type=float, default=30.0, help="How often to log progress.")
    parser.add_argument(
        "--sleep-seconds", type=float, default=0.0, help="Pause between runs (throttles I/O on a live system)."
    )
    parser.add_argument("--limit", type=int, default=None, help="Only process this many runs (for trialling).")
    parser.add_argument(
        "--retry-failed", action="store_true", help=f"Retry runs that have a {FAILED_MARKER_NAME} marker."
    )
    parser.add_argument("--verbose", action="store_true", help="Log every run.")
    args = parser.parse_args(argv)
    if not args.file_store_path:
        parser.error("file_store_path must be specified (or FILE_STORE_PATH set)")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )
    file_store_path = Path(args.file_store_path)
    if not (file_store_path / RUNS_DIR_NAME).is_dir():
        logger.error(f"{file_store_path / RUNS_DIR_NAME} does not exist - is {file_store_path} the file store?")
        return 2

    lock_fd: int | None = None
    if not args.dry_run:
        lock_fd = os.open(file_store_path / MIGRATION_LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o644)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(lock_fd)
            logger.error("Another instance of this migration is already running against this file store")
            return 2

    stop = StopRequested()
    previous_handlers = {sig: signal.signal(sig, stop.handler) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        logger.info(f"Starting migration of {file_store_path} (dry_run={args.dry_run}, keep_legacy={args.keep_legacy})")
        stats = Stats()
        work = survey(file_store_path, stats, args.retry_failed, args.progress_seconds)
        stats.started_at = time.monotonic()  # Don't count the survey in the rate / ETA

        migrator = Migrator(args, stats, stop)
        migrator.run(work)
        report_progress(stats, len(migrator.pending), prefix="STOPPED" if stop.stop else "COMPLETE")
    finally:
        for sig, previous_handler in previous_handlers.items():
            signal.signal(sig, previous_handler)
        if lock_fd is not None:
            os.close(lock_fd)

    if stats.failures:
        logger.error(f"{len(stats.failures):,} runs failed (showing first 50):")
        for failure in stats.failures[:50]:
            logger.error(f"  {failure}")
    if migrator.pending:
        logger.warning(f"{len(migrator.pending):,} legacy dirs still awaiting deletion - rerun to complete.")

    if stats.failures:
        return 1
    return 3 if (stop.stop or migrator.pending) else 0


if __name__ == "__main__":
    sys.exit(main())
