import io
import zipfile

from cactus_orchestrator.chart import (
    _DUMP_SUFFIX,
    _ENVOY_DATA_DUMP_PREFIX,
    _ENVOY_SCHEMA_DUMP_PREFIX,
    extract_envoy_dumps,
)


def _make_zip(**entries: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_extract_envoy_dumps_happy_path():
    schema_sql = b"CREATE TABLE foo ();"
    data_sql = b"INSERT INTO foo VALUES (1);"
    zip_data = _make_zip(
        **{
            f"{_ENVOY_SCHEMA_DUMP_PREFIX}001{_DUMP_SUFFIX}": schema_sql,
            f"{_ENVOY_DATA_DUMP_PREFIX}001{_DUMP_SUFFIX}": data_sql,
            "CactusTestProcedureReport.pdf": b"%PDF-placeholder",
        }
    )
    schema, data = extract_envoy_dumps(zip_data)
    assert schema == schema_sql.decode()
    assert data == data_sql.decode()
