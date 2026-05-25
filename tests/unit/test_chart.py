import io
import zipfile
from datetime import UTC, datetime, timedelta

import pytest

from cactus_orchestrator.power_limit_chart import (
    _EnrichedControl,
    _RawDOE,
    _align_effective_ends_to_client_transitions,
)
from cactus_orchestrator.chart import (
    _DUMP_SUFFIX,
    _ENVOY_DATA_DUMP_PREFIX,
    _ENVOY_SCHEMA_DUMP_PREFIX,
    extract_envoy_dumps,
)


def _make_zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_extract_envoy_dumps_happy_path():
    schema_sql = b"CREATE TABLE foo ();"
    data_sql = b"INSERT INTO foo VALUES (1);"
    zip_data = _make_zip(
        {
            f"{_ENVOY_SCHEMA_DUMP_PREFIX}001{_DUMP_SUFFIX}": schema_sql,
            f"{_ENVOY_DATA_DUMP_PREFIX}001{_DUMP_SUFFIX}": data_sql,
            "CactusTestProcedureReport.pdf": b"%PDF-placeholder",
        }
    )
    schema, data = extract_envoy_dumps(zip_data)
    assert schema == schema_sql.decode()
    assert data == data_sql.decode()


def test_extract_envoy_dumps_missing_schema():
    zip_data = _make_zip(
        {
            f"{_ENVOY_DATA_DUMP_PREFIX}001{_DUMP_SUFFIX}": b"INSERT INTO foo VALUES (1);",
        }
    )
    with pytest.raises(ValueError):
        extract_envoy_dumps(zip_data)


def test_extract_envoy_dumps_missing_data():
    zip_data = _make_zip(
        {
            f"{_ENVOY_SCHEMA_DUMP_PREFIX}001{_DUMP_SUFFIX}": b"CREATE TABLE foo ();",
        }
    )
    with pytest.raises(ValueError):
        extract_envoy_dumps(zip_data)


# ─── _align_effective_ends_to_client_transitions ──────────────────────────────

T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)


def _make_doe(doe_id: int, group_id: int, start: datetime, duration_seconds: int) -> _RawDOE:
    return _RawDOE(
        dynamic_operating_envelope_id=doe_id,
        site_control_group_id=group_id,
        created_time=start,
        start_time=start,
        duration_seconds=duration_seconds,
        superseded=False,
        export_limit_watts=5000.0,
        generation_limit_active_watts=None,
        import_limit_active_watts=None,
        load_limit_active_watts=None,
        set_connected=None,
        set_energized=None,
        ramp_time_seconds=None,
        storage_target_active_watts=None,
        is_archive=False,
        deleted_time=None,
        archive_time=None,
    )


def _make_ctrl(doe: _RawDOE, receipt: datetime, effective_end: datetime) -> _EnrichedControl:
    return _EnrichedControl(
        doe=doe,
        site_control_group_id=doe.site_control_group_id,
        primacy=1,
        receipt_time=receipt,
        effective_start=max(doe.start_time, receipt),
        effective_end=effective_end,
        step_name="",
    )


def test_align_effective_ends_polled_gap_closed():
    """effective_end of a superseded control extends to the next control's receipt_time."""
    # DERC5: created T+0, received T+12s, server-superseded at T+610s
    # DERC6: created T+610s, received T+620s (10s polling gap)
    doe5 = _make_doe(5, group_id=6, start=T0, duration_seconds=1200)
    doe6 = _make_doe(6, group_id=6, start=T0 + timedelta(seconds=610), duration_seconds=300)
    receipt5 = T0 + timedelta(seconds=12)
    receipt6 = T0 + timedelta(seconds=620)
    server_superseded_at = T0 + timedelta(seconds=610)

    ctrl5 = _make_ctrl(doe5, receipt5, effective_end=server_superseded_at)
    ctrl6 = _make_ctrl(doe6, receipt6, effective_end=T0 + timedelta(seconds=910))

    _align_effective_ends_to_client_transitions([ctrl5, ctrl6])

    # ctrl5 should now end when the client actually received ctrl6
    assert ctrl5.effective_end == receipt6
    # ctrl6 (last in group) is unchanged
    assert ctrl6.effective_end == T0 + timedelta(seconds=910)


def test_align_effective_ends_respects_base_end():
    """effective_end is not extended past the control's natural expiry."""
    # DERC5 expires at T+100s; DERC6 is received at T+200s — later than expiry.
    doe5 = _make_doe(5, group_id=6, start=T0, duration_seconds=100)
    doe6 = _make_doe(6, group_id=6, start=T0 + timedelta(seconds=80), duration_seconds=300)
    receipt5 = T0 + timedelta(seconds=5)
    receipt6 = T0 + timedelta(seconds=200)

    ctrl5 = _make_ctrl(doe5, receipt5, effective_end=T0 + timedelta(seconds=80))
    ctrl6 = _make_ctrl(doe6, receipt6, effective_end=T0 + timedelta(seconds=380))

    _align_effective_ends_to_client_transitions([ctrl5, ctrl6])

    # base_end of ctrl5 = T0+100s; receipt6 = T0+200s → min = T0+100s
    assert ctrl5.effective_end == T0 + timedelta(seconds=100)


def test_align_effective_ends_independent_groups():
    """Controls in different groups do not affect each other."""
    doe_a = _make_doe(1, group_id=1, start=T0, duration_seconds=600)
    doe_b = _make_doe(2, group_id=2, start=T0, duration_seconds=600)
    receipt_a = T0 + timedelta(seconds=10)
    receipt_b = T0 + timedelta(seconds=20)
    end_a = T0 + timedelta(seconds=300)
    end_b = T0 + timedelta(seconds=400)

    ctrl_a = _make_ctrl(doe_a, receipt_a, effective_end=end_a)
    ctrl_b = _make_ctrl(doe_b, receipt_b, effective_end=end_b)

    _align_effective_ends_to_client_transitions([ctrl_a, ctrl_b])

    # Single control per group — neither should be modified
    assert ctrl_a.effective_end == end_a
    assert ctrl_b.effective_end == end_b


def test_align_effective_ends_single_control():
    """A group with only one control is unchanged."""
    doe = _make_doe(1, group_id=1, start=T0, duration_seconds=600)
    ctrl = _make_ctrl(doe, receipt=T0 + timedelta(seconds=5), effective_end=T0 + timedelta(seconds=600))

    _align_effective_ends_to_client_transitions([ctrl])

    assert ctrl.effective_end == T0 + timedelta(seconds=600)
