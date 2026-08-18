import io
import zipfile
from dataclasses import dataclass
from pathlib import Path
from time import sleep

import pytest

from cactus_orchestrator.filestore import (
    ERROR_FILE_NAME,
    REPORT_FILE_NAME,
    compliance_finalisation_report_exists,
    fetch_compliance_finalisation_report,
    fetch_run_zip,
    run_zip_exists,
    save_compliance_finalisation_report,
    save_run_finalisation,
    save_run_report,
)


@dataclass
class ActionSaveZip:
    file_data: list[tuple[str, bytes]]


@dataclass
class ActionSaveReport:
    pdf_bytes: bytes


@dataclass
class ActionSaveComplianceReport:
    pdf_bytes: bytes


AnyActionType = ActionSaveReport | ActionSaveZip | ActionSaveComplianceReport


def _apply_actions(path: Path, tenant_id: int, actions: list[AnyActionType]):
    for action in actions:
        if isinstance(action, ActionSaveZip):
            finalisation_zip_buffer = io.BytesIO()
            with zipfile.ZipFile(finalisation_zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
                for name, data in action.file_data:
                    zf.writestr(name, data)
                zf.close()
            finalisation_zip_bytes = finalisation_zip_buffer.getvalue()
            save_run_finalisation(path, tenant_id, finalisation_zip_bytes)
        elif isinstance(action, ActionSaveComplianceReport):
            save_compliance_finalisation_report(path, tenant_id, action.pdf_bytes)
            sleep(0.05)  # If we are writing multiple timestamps - we have microsecond resolution but add a short wait
        else:
            save_run_report(path, tenant_id, action.pdf_bytes)
            sleep(0.05)  # If we are writing multiple timestamps - we have microsecond resolution but add a short wait


@pytest.mark.parametrize(
    "actions, expected_files, expect_error",
    [
        (
            [
                ActionSaveZip([("requests/req1.txt", b"mydata1"), ("data.json", b"mydata2")]),
                ActionSaveReport(b"pdfdata1"),
            ],
            [("requests/req1.txt", b"mydata1"), ("data.json", b"mydata2"), (REPORT_FILE_NAME, b"pdfdata1")],
            False,
        ),
        (
            [
                ActionSaveReport(b"pdfdata1"),
                ActionSaveZip([("requests/req1.txt", b"mydata1"), ("data.json", b"mydata2")]),
            ],
            [("requests/req1.txt", b"mydata1"), ("data.json", b"mydata2"), (REPORT_FILE_NAME, b"pdfdata1")],
            False,
        ),
        (
            [
                ActionSaveReport(b"pdfdata1"),
                ActionSaveReport(b"pdfdata2"),
                ActionSaveZip([("requests/req1.txt", b"mydata1"), ("data.json", b"mydata2")]),
            ],
            [("requests/req1.txt", b"mydata1"), ("data.json", b"mydata2"), (REPORT_FILE_NAME, b"pdfdata2")],
            False,
        ),
        (
            [
                ActionSaveReport(b"pdfdata1"),
                ActionSaveZip([("requests/req1.txt", b"mydata1"), ("data.json", b"mydata2")]),
                ActionSaveReport(b"pdfdata2"),
            ],
            [("requests/req1.txt", b"mydata1"), ("data.json", b"mydata2"), (REPORT_FILE_NAME, b"pdfdata2")],
            False,
        ),
        (
            [
                ActionSaveReport(b"pdfdata1"),
                ActionSaveZip([("requests/req1.txt", b"mydata1"), ("data.log", b"mydata2"), ("data.json", b"mydata3")]),
                ActionSaveReport(b"pdfdata2"),
                ActionSaveZip(
                    [("requests/req1.txt", b"mydata4"), ("requests/req2.txt", b"mydata5"), ("data.json", b"mydata6")]
                ),
            ],
            [
                ("requests/req1.txt", b"mydata4"),
                ("requests/req2.txt", b"mydata5"),
                ("data.log", b"mydata2"),
                ("data.json", b"mydata6"),
                (REPORT_FILE_NAME, b"pdfdata2"),
            ],  # This will merge the two zips
            False,
        ),
        (
            [
                ActionSaveReport(b"pdfdata1"),
            ],
            [(REPORT_FILE_NAME, b"pdfdata1")],
            True,  # Missing ZIP archive
        ),
        (
            [
                ActionSaveZip([("requests/req2.txt", b"mydata3"), ("data.json", b"mydata4")]),
            ],
            [("requests/req2.txt", b"mydata3"), ("data.json", b"mydata4")],
            True,  # Missing Report
        ),
    ],
)
def test_save_and_load_run_finalisation(
    tmp_path: Path,
    actions: list[AnyActionType],
    expected_files: list[tuple[str, bytes]],
    expect_error: bool,
):
    """Tests the various ways saving file contents can interact with the final ZIP"""
    # Arrange - run all the save actions
    run_id = 123
    _apply_actions(tmp_path, run_id, actions)

    # Act / Assert
    expected_files_dict = dict(expected_files)
    with zipfile.ZipFile(io.BytesIO(fetch_run_zip(tmp_path, run_id))) as zf:
        found_error_file = False
        for f in zf.filelist:
            if f.filename == ERROR_FILE_NAME:
                found_error_file = True
            else:
                assert f.filename in expected_files_dict
                assert zf.read(f.filename) == expected_files_dict[f.filename]
                del expected_files_dict[f.filename]

        assert len(expected_files_dict.keys()) == 0, (
            f"Didn't find these files in the Zip archive {expected_files_dict.keys()}"
        )
        assert found_error_file == expect_error


def test_fetch_run_zip_missing(tmp_path: Path):
    with zipfile.ZipFile(io.BytesIO(fetch_run_zip(tmp_path, 123))) as zf:
        assert len(zf.read(ERROR_FILE_NAME)) > 0
        assert len(zf.filelist) == 1

    with zipfile.ZipFile(io.BytesIO(fetch_run_zip(tmp_path, 123, ["fake error"]))) as zf:
        assert b"fake error" in zf.read(ERROR_FILE_NAME)
        assert len(zf.filelist) == 1


def test_fetch_run_zip_inject_error(tmp_path: Path):
    """Can fetch_run_zip properly integrate errors into the output zip"""

    # With no existing error
    run_id = 1
    _apply_actions(tmp_path, run_id, [ActionSaveReport(b"pdfdata1"), ActionSaveZip([("data.txt", b"mydata1")])])

    with zipfile.ZipFile(io.BytesIO(fetch_run_zip(tmp_path, run_id, ["my custom error", "another error"]))) as zf:
        error_data = zf.read(ERROR_FILE_NAME).decode()
        lines = error_data.split("\n")
        assert "my custom error" in lines
        assert "another error" in lines
        assert len(lines) == 2

    # With an existing error (no ZIP data)
    run_id = 2
    _apply_actions(tmp_path, run_id, [ActionSaveZip([("data.txt", b"mydata1")])])
    with zipfile.ZipFile(io.BytesIO(fetch_run_zip(tmp_path, run_id, ["my custom error", "another error"]))) as zf:
        assert zf.read("data.txt") == b"mydata1"
        error_data = zf.read(ERROR_FILE_NAME).decode()
        lines = error_data.split("\n")
        assert "my custom error" in lines
        assert "another error" in lines
        assert len(lines) > 2, "There should be error info about the missing ZIP"

    # With an existing error (no Report data)
    run_id = 3
    _apply_actions(tmp_path, run_id, [ActionSaveReport(b"pdfdata1")])
    with zipfile.ZipFile(io.BytesIO(fetch_run_zip(tmp_path, run_id, ["my custom error", "another error"]))) as zf:
        assert zf.read(REPORT_FILE_NAME) == b"pdfdata1"
        error_data = zf.read(ERROR_FILE_NAME).decode()
        lines = error_data.split("\n")
        assert "my custom error" in lines
        assert "another error" in lines
        assert len(lines) > 2, "There should be error info about the missing report"


@pytest.mark.parametrize(
    "actions, expected",
    [
        (
            [
                ActionSaveZip([("file.txt", b"mydata1")]),
                ActionSaveReport(b"pdfdata1"),
            ],
            True,
        ),
        (
            [
                ActionSaveReport(b"pdfdata1"),
            ],
            True,
        ),
        (
            [
                ActionSaveZip([("file.txt", b"mydata1")]),
            ],
            True,
        ),
        (
            [
                ActionSaveComplianceReport(b"mydata1"),
            ],
            False,  # Compliance report data is NOT run data
        ),
        (
            [],
            False,
        ),
    ],
)
def test_run_zip_exists(tmp_path: Path, actions: list[AnyActionType], expected: bool):
    run_id = 123
    _apply_actions(tmp_path, run_id, actions)
    assert run_zip_exists(tmp_path, run_id) is expected
    assert run_zip_exists(tmp_path, run_id + 1) is False
    assert run_zip_exists(tmp_path, 0) is False
    assert run_zip_exists(tmp_path, -1) is False


def test_segmented_run_dirs(tmp_path: Path):
    """Tests that multiple runs will remain seperate to eachother"""
    run_1_id = 123
    run_2_id = 456

    # Nothing in there to begin
    assert run_zip_exists(tmp_path, run_1_id) is False
    assert run_zip_exists(tmp_path, run_2_id) is False

    _apply_actions(tmp_path, run_1_id, [ActionSaveReport(b"pdfdata1"), ActionSaveZip([("file.txt", b"file1")])])
    _apply_actions(tmp_path, run_2_id, [ActionSaveReport(b"pdfdata2"), ActionSaveZip([("file.txt", b"file2")])])

    with zipfile.ZipFile(io.BytesIO(fetch_run_zip(tmp_path, run_1_id))) as zf:
        assert zf.read(REPORT_FILE_NAME) == b"pdfdata1"
        assert zf.read("file.txt") == b"file1"
        assert len(zf.filelist) == 2

    with zipfile.ZipFile(io.BytesIO(fetch_run_zip(tmp_path, run_2_id))) as zf:
        assert zf.read(REPORT_FILE_NAME) == b"pdfdata2"
        assert zf.read("file.txt") == b"file2"
        assert len(zf.filelist) == 2


@pytest.mark.parametrize(
    "actions, expected",
    [
        (
            [
                ActionSaveComplianceReport(b"pdfdata1"),
            ],
            True,
        ),
        (
            [
                ActionSaveComplianceReport(b"pdfdata1"),
                ActionSaveComplianceReport(b"pdfdata2"),
            ],
            True,
        ),
        (
            [
                ActionSaveZip([("file.txt", b"mydata1")]),
                ActionSaveReport(b"pdfdata1"),
            ],
            False,  # This is testing compliance reports - not run data
        ),
        (
            [],
            False,
        ),
    ],
)
def test_compliance_finalisation_report_exists(tmp_path: Path, actions: list[AnyActionType], expected: bool):
    compliance_finalisation_id = 123
    _apply_actions(tmp_path, compliance_finalisation_id, actions)
    assert compliance_finalisation_report_exists(tmp_path, compliance_finalisation_id) is expected
    assert compliance_finalisation_report_exists(tmp_path, compliance_finalisation_id + 1) is False
    assert compliance_finalisation_report_exists(tmp_path, 0) is False
    assert compliance_finalisation_report_exists(tmp_path, -1) is False


@pytest.mark.parametrize(
    "id_actions, expected",
    [
        (
            [
                (123, ActionSaveComplianceReport(b"pdfdata1")),
            ],
            [(123, b"pdfdata1"), (99, None), (0, None)],
        ),
        (
            [
                (123, ActionSaveComplianceReport(b"pdfdata1")),
                (123, ActionSaveComplianceReport(b"pdfdata2")),
            ],
            [(123, b"pdfdata2")],
        ),
        (
            [
                (123, ActionSaveComplianceReport(b"pdfdata1")),
                (456, ActionSaveComplianceReport(b"pdfdata2")),
                (123, ActionSaveComplianceReport(b"pdfdata3")),
            ],
            [(123, b"pdfdata3"), (456, b"pdfdata2"), (124, None)],
        ),
        (
            [],
            [(123, None)],
        ),
    ],
)
def test_save_fetch_compliance_finalisation_report(
    tmp_path: Path, id_actions: list[tuple[int, AnyActionType]], expected: list[tuple[int, bytes | None]]
):
    """Test the compliance finalisation saving/fetching"""

    # Setup the store
    for compliance_id, action in id_actions:
        _apply_actions(tmp_path, compliance_id, [action])

    for compliance_id, expected_data in expected:
        actual = fetch_compliance_finalisation_report(tmp_path, compliance_id)
        assert actual is None or isinstance(actual, bytes)
        assert actual == expected_data
