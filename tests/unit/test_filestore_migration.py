import fcntl
import io
import os
import zipfile
from pathlib import Path

import pytest

from cactus_orchestrator import filestore, filestore_migration
from cactus_orchestrator.filestore import (
    fetch_run_finalised_file,
    fetch_run_zip,
    list_run_finalised_files,
    run_directory,
    run_zip_exists,
    save_run_finalisation,
    save_run_report,
)
from cactus_orchestrator.filestore_migration import FAILED_MARKER_NAME, MIGRATION_LOCK_NAME, main


def make_zip(files: list[tuple[str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files:
            zf.writestr(name, data)
    return buffer.getvalue()


def save_legacy_finalisation(file_store_path: Path, run_id: int, files: list[tuple[str, bytes]]) -> Path:
    """Replicates the (old) behaviour of save_run_finalisation - extracting the zip to disk"""
    legacy_dir = run_directory(file_store_path, run_id) / "finalise"
    legacy_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(make_zip(files))) as zf:
        zf.extractall(legacy_dir)
    return legacy_dir


def zip_contents(data: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return {i.filename: zf.read(i) for i in zf.infolist() if not i.is_dir()}


def snapshot(file_store_path: Path, run_id: int) -> tuple:
    """Everything the orchestrator can observe about a run's finalisation data"""
    return (
        sorted(list_run_finalised_files(file_store_path, run_id)),
        sorted(list_run_finalised_files(file_store_path, run_id, filter="*.req")),
        sorted(list_run_finalised_files(file_store_path, run_id, filter="EnvoyDB_*.dump")),
        fetch_run_finalised_file(file_store_path, run_id, "requests/1.req"),
        fetch_run_finalised_file(file_store_path, run_id, "EnvoyDB_123.dump"),
        zip_contents(fetch_run_zip(file_store_path, run_id)),
        run_zip_exists(file_store_path, run_id),
    )


RUN_FILES = [
    ("EnvoyDB_123.dump", b"db dump"),
    ("ReportingData_v1_123.json", b"{}"),
    ("requests/1.req", b"req1"),
    ("requests/1.resp", b"resp1"),
    ("requests/2.req", b"req2"),
    ("requests/sub/2.resp", b"resp2"),
]


def test_constants_match_filestore():
    """filestore_migration is standalone - so it duplicates some constants that MUST match"""
    assert filestore_migration.FINALISE_ZIP_NAME == filestore.FINALISE_ZIP_NAME
    assert filestore_migration.LEGACY_FINALISE_DIR_NAME == filestore.LEGACY_FINALISE_DIR_NAME
    assert filestore_migration.LEGACY_DELETING_DIR_NAME == filestore.LEGACY_DELETING_DIR_NAME
    assert filestore_migration.TMP_FILE_SUFFIX == filestore.TMP_FILE_SUFFIX

    run_dir = run_directory(Path("/root"), 123456)
    assert run_dir.parent.parent.name == filestore_migration.RUNS_DIR_NAME
    assert run_dir.name.startswith(filestore_migration.RUN_DIR_PREFIX)


def test_filestore_module_is_standalone():
    """The migration script must be runnable with a vanilla python (no third party / project imports)"""
    source = Path(filestore_migration.__file__).read_text()
    assert "cactus_orchestrator" not in "\n".join(
        line for line in source.splitlines() if line.startswith(("import ", "from "))
    )


def test_legacy_store_readable(tmp_path: Path):
    """The filestore can still read legacy (extracted) data"""
    save_legacy_finalisation(tmp_path, 1, RUN_FILES)
    save_run_report(tmp_path, 1, b"pdf")

    files, req_files, db_files, req1, db, contents, exists = snapshot(tmp_path, 1)
    assert files == sorted(Path(n) for n, _ in RUN_FILES)
    assert req_files == [Path("requests/1.req"), Path("requests/2.req")]
    assert db_files == [Path("EnvoyDB_123.dump")]
    assert req1 == b"req1"
    assert db == b"db dump"
    assert contents == dict(RUN_FILES) | {filestore.REPORT_FILE_NAME: b"pdf"}
    assert exists is True


def test_save_stores_single_zip_verbatim(tmp_path: Path):
    data = make_zip(RUN_FILES)
    save_run_finalisation(tmp_path, 1, data)

    run_dir = run_directory(tmp_path, 1)
    assert sorted(p.name for p in run_dir.iterdir()) == ["finalise.zip"]
    assert (run_dir / "finalise.zip").read_bytes() == data


def test_save_rejects_corrupt_zip(tmp_path: Path):
    with pytest.raises(zipfile.BadZipFile):
        save_run_finalisation(tmp_path, 1, b"not a zip")
    assert not run_zip_exists(tmp_path, 1)


def test_save_normalises_member_names(tmp_path: Path):
    """Member names are sanitised the same way that extractall used to"""
    save_run_finalisation(tmp_path, 1, make_zip([("./a.txt", b"a"), ("../b.txt", b"b"), ("/c/d.txt", b"d")]))
    assert sorted(list_run_finalised_files(tmp_path, 1)) == [Path("a.txt"), Path("b.txt"), Path("c/d.txt")]
    assert fetch_run_finalised_file(tmp_path, 1, "c/d.txt") == b"d"


def test_save_merges_into_legacy_store(tmp_path: Path):
    """Saving over the top of legacy data merges it into the zip and removes the legacy dir"""
    legacy_dir = save_legacy_finalisation(tmp_path, 1, [("a.txt", b"old-a"), ("sub/b.txt", b"old-b")])
    save_run_finalisation(tmp_path, 1, make_zip([("a.txt", b"new-a"), ("c.txt", b"new-c")]))

    assert not legacy_dir.exists()
    assert not (legacy_dir.parent / "finalise.deleting").exists()
    assert zip_contents((legacy_dir.parent / "finalise.zip").read_bytes()) == {
        "a.txt": b"new-a",
        "sub/b.txt": b"old-b",
        "c.txt": b"new-c",
    }


def run_migration(tmp_path: Path, *args: str) -> int:
    return main([str(tmp_path), "--grace-seconds", "0", "--progress-seconds", "0", *args])


def test_migration_end_to_end(tmp_path: Path):
    # Mix of legacy runs, new style runs, report only runs and an empty legacy dir
    for run_id in [1, 2, 1001, 2002]:
        save_legacy_finalisation(tmp_path, run_id, RUN_FILES + [("unique.txt", str(run_id).encode())])
        save_run_report(tmp_path, run_id, f"pdf{run_id}".encode())
    save_run_finalisation(tmp_path, 3, make_zip(RUN_FILES))
    save_run_report(tmp_path, 4, b"pdf4")
    (run_directory(tmp_path, 5) / "finalise").mkdir(parents=True)

    run_ids = [1, 2, 3, 4, 5, 1001, 2002, 999]
    before = {run_id: snapshot(tmp_path, run_id) for run_id in run_ids}

    assert run_migration(tmp_path) == 0

    for run_id in run_ids:
        assert snapshot(tmp_path, run_id) == before[run_id], f"run {run_id} changed"
    for run_id in [1, 2, 3, 5, 1001, 2002]:
        run_dir = run_directory(tmp_path, run_id)
        assert (run_dir / "finalise.zip").is_file()
        assert not (run_dir / "finalise").exists()
        assert not (run_dir / "finalise.zip.tmp").exists()
        assert not (run_dir / FAILED_MARKER_NAME).exists()

    # Idempotent
    assert run_migration(tmp_path) == 0
    for run_id in run_ids:
        assert snapshot(tmp_path, run_id) == before[run_id]


def test_migration_dry_run_writes_nothing(tmp_path: Path):
    save_legacy_finalisation(tmp_path, 1, RUN_FILES)
    (run_directory(tmp_path, 2) / "finalise").mkdir(parents=True)
    os.symlink("/etc/passwd", run_directory(tmp_path, 2) / "finalise" / "link")
    before = sorted(str(p) for p in tmp_path.rglob("*"))

    assert run_migration(tmp_path, "--dry-run") == 1  # The symlink should be reported
    assert sorted(str(p) for p in tmp_path.rglob("*")) == before


def test_migration_keep_legacy_then_delete(tmp_path: Path):
    legacy_dir = save_legacy_finalisation(tmp_path, 1, RUN_FILES)
    before = snapshot(tmp_path, 1)

    assert run_migration(tmp_path, "--keep-legacy") == 0
    assert legacy_dir.is_dir()
    assert (legacy_dir.parent / "finalise.zip").is_file()
    assert snapshot(tmp_path, 1) == before

    assert run_migration(tmp_path) == 0
    assert not legacy_dir.exists()
    assert snapshot(tmp_path, 1) == before


def test_migration_grace_period_respected(tmp_path: Path):
    """If interrupted before the grace period elapses - the legacy data remains"""
    legacy_dir = save_legacy_finalisation(tmp_path, 1, RUN_FILES)

    with pytest.MonkeyPatch.context() as mp:
        # Simulate being interrupted while waiting for the grace period
        def fake_sleep(seconds: float) -> None:
            raise KeyboardInterrupt()

        mp.setattr(filestore_migration.time, "sleep", fake_sleep)
        with pytest.raises(KeyboardInterrupt):
            main([str(tmp_path), "--grace-seconds", "3600"])

    assert legacy_dir.is_dir()
    assert (legacy_dir.parent / "finalise.zip").is_file()


def test_migration_crash_leftovers(tmp_path: Path):
    """Simulates the state left behind by crashes at various points"""
    # Crash mid zip write
    save_legacy_finalisation(tmp_path, 1, RUN_FILES)
    (run_directory(tmp_path, 1) / "finalise.zip.tmp").write_bytes(b"partial garbage")

    # Crash after zip written, but before legacy deleted
    save_legacy_finalisation(tmp_path, 2, RUN_FILES)
    run_dir_2 = run_directory(tmp_path, 2)
    (run_dir_2 / "finalise.zip").write_bytes(make_zip(RUN_FILES))

    # Crash mid legacy delete (renamed, partially deleted)
    deleting_dir = save_legacy_finalisation(tmp_path, 3, RUN_FILES[:2]).rename(
        run_directory(tmp_path, 3) / "finalise.deleting"
    )
    (run_directory(tmp_path, 3) / "finalise.zip").write_bytes(make_zip(RUN_FILES))

    before = {run_id: zip_contents(make_zip(RUN_FILES)) for run_id in [1, 2, 3]}
    assert run_migration(tmp_path) == 0

    for run_id in [1, 2, 3]:
        run_dir = run_directory(tmp_path, run_id)
        assert sorted(p.name for p in run_dir.iterdir()) == ["finalise.zip"]
        assert zip_contents((run_dir / "finalise.zip").read_bytes()) == before[run_id]
    assert not deleting_dir.exists()


def test_migration_mismatch_is_never_deleted(tmp_path: Path):
    """If the legacy dir doesn't match the existing zip - nothing is deleted and the run is flagged"""
    legacy_dir = save_legacy_finalisation(tmp_path, 1, RUN_FILES)
    run_dir = run_directory(tmp_path, 1)
    (run_dir / "finalise.zip").write_bytes(make_zip([(n, b"different") for n, _ in RUN_FILES]))

    # Deleting dir without a zip
    deleting_dir = run_directory(tmp_path, 2) / "finalise.deleting"
    deleting_dir.mkdir(parents=True)
    (deleting_dir / "a.txt").write_bytes(b"a")

    assert run_migration(tmp_path) == 1
    assert sorted(p.relative_to(legacy_dir).as_posix() for p in legacy_dir.rglob("*") if p.is_file()) == sorted(
        n for n, _ in RUN_FILES
    )
    assert "but" in (run_dir / FAILED_MARKER_NAME).read_text()  # Describes the digest mismatch
    assert (deleting_dir / "a.txt").read_bytes() == b"a"
    assert (run_directory(tmp_path, 2) / FAILED_MARKER_NAME).is_file()

    # Failed runs are skipped on rerun (and still untouched)
    assert run_migration(tmp_path) == 0
    assert legacy_dir.is_dir()
    assert deleting_dir.is_dir()

    # Unless explicitly retried
    assert run_migration(tmp_path, "--retry-failed") == 1
    assert legacy_dir.is_dir()


def test_migration_failure_then_retry(tmp_path: Path):
    """A failed conversion leaves the legacy data intact, and can be retried once the cause is fixed"""
    legacy_dir = save_legacy_finalisation(tmp_path, 1, RUN_FILES)
    save_legacy_finalisation(tmp_path, 2, RUN_FILES)
    link = legacy_dir / "link"
    os.symlink("/etc/passwd", link)

    assert run_migration(tmp_path) == 1
    run_dir = run_directory(tmp_path, 1)
    assert legacy_dir.is_dir()
    assert not (run_dir / "finalise.zip").exists()
    assert not (run_dir / "finalise.zip.tmp").exists()
    assert "Symlink" in (run_dir / FAILED_MARKER_NAME).read_text()
    assert (run_directory(tmp_path, 2) / "finalise.zip").is_file(), "Other runs should NOT be impacted"

    link.unlink()
    before = snapshot(tmp_path, 1)
    assert run_migration(tmp_path, "--retry-failed") == 0
    assert sorted(p.name for p in run_dir.iterdir()) == ["finalise.zip"]
    assert snapshot(tmp_path, 1) == before


def test_migration_verification_failure_rolls_back(tmp_path: Path):
    """If the written zip fails verification - it's never put in place"""
    legacy_dir = save_legacy_finalisation(tmp_path, 1, RUN_FILES)

    with pytest.MonkeyPatch.context() as mp:

        def bad_digests(zip_path: Path) -> dict:
            return {}

        mp.setattr(filestore_migration, "read_zip_digests", bad_digests)
        assert run_migration(tmp_path) == 1

    run_dir = run_directory(tmp_path, 1)
    assert legacy_dir.is_dir()
    assert not (run_dir / "finalise.zip").exists()
    assert not (run_dir / "finalise.zip.tmp").exists()


def test_migration_single_instance(tmp_path: Path):
    save_legacy_finalisation(tmp_path, 1, RUN_FILES)
    with open(tmp_path / MIGRATION_LOCK_NAME, "w") as fp:
        fcntl.flock(fp.fileno(), fcntl.LOCK_EX)
        assert run_migration(tmp_path) == 2
    assert run_migration(tmp_path) == 0


def test_migration_limit(tmp_path: Path):
    for run_id in [1, 2, 3]:
        save_legacy_finalisation(tmp_path, run_id, RUN_FILES)
    assert run_migration(tmp_path, "--limit", "2") == 0
    assert sum((run_directory(tmp_path, r) / "finalise.zip").is_file() for r in [1, 2, 3]) == 2
    assert run_migration(tmp_path) == 0
    assert all((run_directory(tmp_path, r) / "finalise.zip").is_file() for r in [1, 2, 3])


def test_migration_bad_path(tmp_path: Path):
    assert main([str(tmp_path / "dne")]) == 2
