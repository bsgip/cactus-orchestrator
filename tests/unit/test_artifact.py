import io
import zipfile

import pytest
from assertical.fake.generator import generate_class_instance
from cactus_runner.models import ActiveTestProcedure, CheckResult, ReportingData, ResourceAnnotations, RunnerState
from cactus_test_definitions.client import TestProcedureId, get_test_procedure

from cactus_orchestrator.artifact import regenerate_run_artifact, replace_pdf_in_zip_data
from cactus_orchestrator.model import RunArtifact


@pytest.mark.parametrize("original_data, replacement_data", [(b"before", b"after"), (b"before", b"before")])
def test_replace_pdf_in_zip_data(original_data: bytes, replacement_data: bytes):
    PDF_FILENAME = f"CactusTestProcedureReport.pdf"
    TXT_FILENAME = "other_file.txt"
    TXT_DATA = b"other"

    # Arrange
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        with archive.open(PDF_FILENAME, "w") as file:
            file.write(original_data)
        with archive.open(TXT_FILENAME, "w") as file:
            file.write(TXT_DATA)

    zip_data = zip_buffer.getvalue()

    # Act
    updated_zip_data = replace_pdf_in_zip_data(
        pdf_data=replacement_data, zip_data=zip_data, pdf_filename_prefix=PDF_FILENAME
    )

    # Assert
    if replacement_data == original_data:  # the replacement was the same as the original
        assert updated_zip_data == zip_data
    with zipfile.ZipFile(io.BytesIO(updated_zip_data)) as archive:
        assert len(archive.namelist()) == 2
        assert PDF_FILENAME in archive.namelist()
        assert TXT_FILENAME in archive.namelist()
        assert archive.read(PDF_FILENAME) == replacement_data
        assert archive.read(TXT_FILENAME) == TXT_DATA


@pytest.fixture
def run_artifact() -> RunArtifact:
    PDF_FILENAME = f"CactusTestProcedureReport.pdf"
    TXT_FILENAME = "other_file.txt"
    PDF_DATA = b"before"
    TXT_DATA = b"other"

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        with archive.open(PDF_FILENAME, "w") as file:
            file.write(PDF_DATA)
        with archive.open(TXT_FILENAME, "w") as file:
            file.write(TXT_DATA)

    zip_data = zip_buffer.getvalue()

    runner_state = generate_class_instance(
        RunnerState,
        active_test_procedure=generate_class_instance(
            ActiveTestProcedure,
            definition=get_test_procedure(test_procedure_id=TestProcedureId.ALL_01),
            step_status={},
            finished_zip_data=None,
            resource_annotations=ResourceAnnotations(der_control_ids_by_alias={"a": 1}),
        ),
    )
    reporting_data = generate_class_instance(
        ReportingData, check_results={"key": generate_class_instance(CheckResult)}, runner_state=runner_state
    )
    reporting_data_json = reporting_data.to_json()
    artifact = RunArtifact(compression="gzip", file_data=zip_data, reporting_data=reporting_data_json)
    return artifact


def test_regenerate_run_artifact(run_artifact: RunArtifact):

    # Act
    updated_artifact = regenerate_run_artifact(run_artifact=run_artifact)

    # Assert
    assert isinstance(updated_artifact, RunArtifact)


def test_regenerate_run_artifact_raises_exception(run_artifact: RunArtifact):
    original_reporting_data = run_artifact.reporting_data

    with pytest.raises(ValueError) as excinfo:
        run_artifact.reporting_data = None
        regenerate_run_artifact(run_artifact=run_artifact)
    assert "No reporting data" in str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        run_artifact.reporting_data = "{}"  # not valid reporting data json
        regenerate_run_artifact(run_artifact=run_artifact)
    assert "Failed to convert json" in str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        run_artifact.reporting_data = original_reporting_data
        run_artifact.file_data = b""  # not valid zip file
        regenerate_run_artifact(run_artifact=run_artifact)
    assert "Failed to replace pdf in archive" in str(excinfo.value)
