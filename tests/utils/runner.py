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

TEST_FINALISATION_DATA = [
    ("random_file.txt", b"filedata1"),
    ("requests/1.request", b"filedata2"),
    ("requests/1.response", b"filedata3"),
]


def create_runner_finalisation_zip(
    has_finalisation_data: bool = False,
    reporting_data_version_json: tuple[int, str] | None = None,
    envoy_db_schema: tuple[str | bytes | None, str | bytes | None] | None = None,
) -> bytes:
    """Generates a ZIP that emulates what a v1 runner would return during finalisation

    reporting_data_version_json: (version, json)
    envoy_db_schema: (schema_sql, data_sql)
    """
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

    return zip_buffer.getvalue()
