import io
import zipfile

from cactus_orchestrator.artifact import (
    ENVOY_DB_DATA_PREFIX,
    ENVOY_DB_DATA_SUFFIX,
    ENVOY_DB_SCHEMA_PREFIX,
    ENVOY_DB_SCHEMA_SUFFIX,
    REPORTING_DATA_PREFIX,
    REPORTING_DATA_SUFFIX,
)
from cactus_orchestrator.filestore import save_run_finalisation, save_run_report
from cactus_orchestrator.settings import get_current_settings

TEST_FINALISATION_DATA = [
    ("random_file.txt", b"filedata1"),
    ("requests/1.request", b"filedata2"),
    ("requests/1.response", b"filedata3"),
]


def load_file_store_for_test(
    run_id: int,
    has_finalisation_data: bool = False,
    reporting_data_version_json: tuple[int, str] | None = None,
    envoy_db_schema: tuple[str | bytes | None, str | bytes | None] | None = None,
    existing_report_bytes: bytes | None = None,
) -> None:
    """Loads the filestore for a particular run with the specified values

    reporting_data_version_json: (version, json)
    envoy_db_schema: (schema_sql, data_sql)
    """
    settings = get_current_settings()

    # Write zip data
    if has_finalisation_data or reporting_data_version_json:
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
            if has_finalisation_data:
                for arcname, arcdata in TEST_FINALISATION_DATA:
                    archive.writestr(arcname, arcdata)

            if reporting_data_version_json is not None:
                version, json_data = reporting_data_version_json
                archive.writestr(f"{REPORTING_DATA_PREFIX}{version}_foo_{REPORTING_DATA_SUFFIX}", json_data)

            if envoy_db_schema is not None:
                schema_sql, data_sql = envoy_db_schema
                if schema_sql is not None:
                    archive.writestr(f"{ENVOY_DB_SCHEMA_PREFIX}_foo_{ENVOY_DB_SCHEMA_SUFFIX}", schema_sql)
                if data_sql is not None:
                    archive.writestr(f"{ENVOY_DB_DATA_PREFIX}_foo_{ENVOY_DB_DATA_SUFFIX}", data_sql)

        zip_data = zip_buffer.getvalue()
        save_run_finalisation(settings.file_store_path, run_id, zip_data)

    # Write report data
    if existing_report_bytes is not None:
        save_run_report(settings.file_store_path, run_id, existing_report_bytes)
