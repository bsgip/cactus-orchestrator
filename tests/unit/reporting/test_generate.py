import io
from datetime import UTC, datetime

import pandas as pd
import pytest
from assertical.fake.generator import generate_class_instance
from cactus_runner.app.readings import scale_readings
from cactus_runner.models import (
    ActiveTestProcedure,
    CheckResult,
    PackedReadings,
    ReadingType,
    ReportingData_v1,
    ResourceAnnotations,
    RunnerState,
)
from cactus_schema.runner import ClientInteraction, ClientInteractionType
from cactus_test_definitions.client import TestProcedureId, get_test_procedure
from envoy.server.model.site_reading import SiteReading, SiteReadingType

from cactus_orchestrator.reporting.generate import generate_pdf_report_v1

# Datetime columns present in the SiteReading model that end up in the readings DataFrame
_SITE_READING_DATETIME_COLUMNS = ["time_period_start", "created_time", "changed_time"]


def test_readings_dataframe_round_trip_preserves_datetime_columns():
    """Verifies the to_json()/read_json() round-trip (runner - orchestrator) preserves datetime columns.

    pd.read_json() convert_dates detects column names containing '_time' only so time_period_start comes back as int64.
    This test ensures that created_time and changed_time (both contain '_time') are detected and converted, and that
    the orchestrator side deserialisation method works.
    """
    t_start = datetime(2026, 2, 1, 12, 0, 0, tzinfo=UTC)
    t_created = datetime(2026, 2, 1, 11, 0, 0, tzinfo=UTC)
    t_changed = datetime(2026, 2, 1, 11, 30, 0, tzinfo=UTC)

    reading = generate_class_instance(
        SiteReading, time_period_start=t_start, created_time=t_created, changed_time=t_changed, value=100
    )
    reading_type = generate_class_instance(SiteReadingType, power_of_ten_multiplier=0)

    # Serialise as the runner does in finalize.py
    original_df = scale_readings(reading_type=reading_type, readings=[reading])
    json_str = original_df.to_json()

    # Raw pd.read_json() leaves time_period_start as int64
    raw_df = pd.read_json(io.StringIO(json_str))
    assert not pd.api.types.is_datetime64_any_dtype(raw_df["time_period_start"])

    # created_time and changed_time contain '_time' so pandas does auto-detect them
    assert pd.api.types.is_datetime64_any_dtype(raw_df["created_time"])
    assert pd.api.types.is_datetime64_any_dtype(raw_df["changed_time"])

    # After the explicit conversion (same applied in generate.py), all columns are proper datetimes
    result_df = pd.read_json(io.StringIO(json_str))
    result_df["time_period_start"] = pd.to_datetime(result_df["time_period_start"], unit="ms", utc=True)

    for col in _SITE_READING_DATETIME_COLUMNS:
        assert pd.api.types.is_datetime64_any_dtype(result_df[col]), f"{col} should be datetime dtype after round-trip"

    # time_period_start is explicitly converted to UTC-aware; the auto-detected columns are tz-naive
    assert result_df["time_period_start"].iloc[0] == pd.Timestamp(t_start)
    assert result_df["created_time"].iloc[0] == pd.Timestamp(t_created).tz_convert(None)
    assert result_df["changed_time"].iloc[0] == pd.Timestamp(t_changed).tz_convert(None)


@pytest.mark.asyncio
async def test_generate_pdf_report_v1():
    # Arrange
    runner_state = generate_class_instance(
        RunnerState,
        active_test_procedure=generate_class_instance(
            ActiveTestProcedure,
            definition=get_test_procedure(test_procedure_id=TestProcedureId.ALL_01),
            step_status={},
            finished_zip_path=None,
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


@pytest.mark.asyncio
async def test_generate_pdf_report_v1_with_readings():
    """Tests end-to-end PDF generation with readings that have gone through the runner - orchestrator JSON round-trip.

    Uses the relative-timeline subtraction in generate_readings_timeline that previously failed with:
        TypeError: numpy.ndarray - Timestamp due to int64 datetime columns.
    """
    t_start = datetime(2024, 3, 1, 12, 0, 0, tzinfo=UTC)

    reading = generate_class_instance(SiteReading, time_period_start=t_start, value=100)
    reading_type = generate_class_instance(SiteReadingType, power_of_ten_multiplier=0)

    # Build PackedReadings as finalize.py does: DataFrame to_json()
    df = scale_readings(reading_type=reading_type, readings=[reading])
    packed = PackedReadings(
        reading_type=generate_class_instance(ReadingType), readings_as_json=df.to_json(), reading_counts=1
    )

    # RunnerState with TEST_PROCEDURE_START so generate_readings_timeline takes the
    # relative-time path (readings_df[x_axis_column] - base_timestamp)
    runner_state = generate_class_instance(
        RunnerState,
        active_test_procedure=generate_class_instance(
            ActiveTestProcedure,
            definition=get_test_procedure(test_procedure_id=TestProcedureId.ALL_01),
            step_status={},
            finished_zip_path=None,
            resource_annotations=ResourceAnnotations(der_control_ids_by_alias={"a": 1}),
        ),
        client_interactions=[
            generate_class_instance(
                ClientInteraction,
                interaction_type=ClientInteractionType.TEST_PROCEDURE_START,
                timestamp=t_start,
            )
        ],
    )

    reporting_data = generate_class_instance(
        ReportingData_v1, check_results={}, runner_state=runner_state, readings=[packed], sites=[], timeline=None
    )

    pdf_data = await generate_pdf_report_v1(reporting_data=reporting_data)

    assert isinstance(pdf_data, bytes)
    assert len(pdf_data) > 0
