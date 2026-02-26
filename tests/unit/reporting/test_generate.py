import pytest
from assertical.fake.generator import generate_class_instance
from cactus_runner.models import ActiveTestProcedure, CheckResult, ReportingData_v1, ResourceAnnotations, RunnerState
from cactus_test_definitions.client import TestProcedureId, get_test_procedure

from cactus_orchestrator.reporting.generate import generate_pdf_report_v1


@pytest.mark.asyncio
async def test_generate_pdf_report_v1():
    # Arrange
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
        ReportingData_v1, check_results={"key": generate_class_instance(CheckResult)}, runner_state=runner_state
    )

    # Act
    pdf_data = await generate_pdf_report_v1(reporting_data=reporting_data)

    # Assert
    assert isinstance(pdf_data, bytes)
