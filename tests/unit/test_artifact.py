import io
import zipfile
from itertools import product

import pytest

from cactus_orchestrator.artifact import (
    EnvoyDbDump,
    RawReportingData,
    fetch_run_envoy_db,
    fetch_run_reporting_data_json,
)
from cactus_orchestrator.settings import get_current_settings
from tests.utils.filestore import load_file_store_for_test
from tests.utils.runner import create_runner_finalisation_zip


def _make_zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_fetch_run_envoy_db_happy_path():

    # Arrange
    schema_sql = b"CREATE TABLE foo ();"
    data_sql = b"INSERT INTO foo VALUES (1);"
    run_id = 123
    load_file_store_for_test(
        run_id, create_runner_finalisation_zip(has_finalisation_data=True, envoy_db_schema=(schema_sql, data_sql))
    )
    settings = get_current_settings()

    # Act
    db_dump = fetch_run_envoy_db(settings, run_id)

    # Assert
    assert isinstance(db_dump, EnvoyDbDump)
    assert db_dump.schema_sql == schema_sql.decode()
    assert db_dump.data_sql == data_sql.decode()


def test_fetch_run_envoy_db_missing_schema():
    # Arrange
    data_sql = b"INSERT INTO foo VALUES (1);"
    run_id = 123
    load_file_store_for_test(
        run_id, create_runner_finalisation_zip(has_finalisation_data=True, envoy_db_schema=(None, data_sql))
    )
    settings = get_current_settings()

    # Act
    db_dump = fetch_run_envoy_db(settings, run_id)

    # Assert
    assert db_dump is None


def test_fetch_run_envoy_db_missing_data():
    # Arrange
    schema_sql = b"CREATE TABLE foo ();"
    run_id = 123
    load_file_store_for_test(
        run_id, create_runner_finalisation_zip(has_finalisation_data=True, envoy_db_schema=(schema_sql, None))
    )
    settings = get_current_settings()

    # Act
    db_dump = fetch_run_envoy_db(settings, run_id)

    # Assert
    assert db_dump is None


@pytest.mark.parametrize("has_finalisation_data, version", product([True, False], [1, 99]))
def test_fetch_run_reporting_data_json(reporting_data_json: str, has_finalisation_data: bool, version: int):
    # Arrange
    run_id = 123
    load_file_store_for_test(
        run_id,
        create_runner_finalisation_zip(
            has_finalisation_data=has_finalisation_data, reporting_data_version_json=(version, reporting_data_json)
        ),
    )
    settings = get_current_settings()

    # Act
    data = fetch_run_reporting_data_json(settings, run_id)

    # Assert
    assert isinstance(data, RawReportingData)
    assert data.raw_json == reporting_data_json
    assert data.version == version


@pytest.mark.parametrize("has_finalisation_data", [True, False])
def test_fetch_run_reporting_data_json_missing(has_finalisation_data):
    # Arrange
    run_id = 123
    load_file_store_for_test(
        run_id,
        create_runner_finalisation_zip(has_finalisation_data=has_finalisation_data, reporting_data_version_json=None),
    )
    settings = get_current_settings()

    # Act
    data = fetch_run_reporting_data_json(settings, run_id)

    # Assert
    assert data is None
