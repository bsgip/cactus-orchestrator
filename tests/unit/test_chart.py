import io
import zipfile
from datetime import UTC, datetime, timedelta
from http import HTTPStatus

import pytest
from cactus_schema.runner.schema import HTTPMethod, RequestEntry

from cactus_orchestrator.chart import (
    _DUMP_SUFFIX,
    _ENVOY_DATA_DUMP_PREFIX,
    _ENVOY_SCHEMA_DUMP_PREFIX,
    extract_envoy_dumps,
)
from cactus_orchestrator.power_limit_chart.db import _RawControlGroup, _RawDefault, _RawDOE
from cactus_orchestrator.power_limit_chart.limits import (
    _build_receipt_markers,
    _compute_disconnect_intervals,
    _get_effective_upper_at,
)
from cactus_orchestrator.power_limit_chart.replay import (
    _FAR_FUTURE,
    _build_control_versions,
    _build_group_observations,
    _collect_poll_observations,
    _KnownControlSegment,
    _Observation,
    _replay_control_knowledge,
    _replay_default_knowledge,
    _version_at,
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


# ─── Client knowledge replay ──────────────────────────────────────────────────

T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)


def _make_doe_row(
    doe_id: int,
    group_id: int,
    start: datetime,
    duration_seconds: int,
    *,
    created: datetime | None = None,
    export_limit: float | None = 5000.0,
    set_connected: bool | None = None,
    superseded: bool = False,
    is_archive: bool = False,
    archive_time: datetime | None = None,
    deleted_time: datetime | None = None,
) -> _RawDOE:
    return _RawDOE(
        dynamic_operating_envelope_id=doe_id,
        site_control_group_id=group_id,
        created_time=created if created is not None else start,
        start_time=start,
        duration_seconds=duration_seconds,
        superseded=superseded,
        export_limit_watts=export_limit,
        generation_limit_active_watts=None,
        import_limit_active_watts=None,
        load_limit_active_watts=None,
        set_connected=set_connected,
        set_energized=None,
        ramp_time_seconds=None,
        storage_target_active_watts=None,
        is_archive=is_archive,
        deleted_time=deleted_time,
        archive_time=archive_time,
    )


def _make_default_row(
    group_id: int,
    changed: datetime,
    *,
    export_limit: float | None = None,
    grad_w: int | None = None,
    is_archive: bool = False,
    archive_time: datetime | None = None,
    deleted_time: datetime | None = None,
) -> _RawDefault:
    return _RawDefault(
        site_control_group_id=group_id,
        changed_time=changed,
        export_limit_active_watts=export_limit,
        generation_limit_active_watts=None,
        import_limit_active_watts=None,
        load_limit_active_watts=None,
        ramp_rate_percent_per_second=grad_w,
        storage_target_active_watts=None,
        is_archive=is_archive,
        deleted_time=deleted_time,
        archive_time=archive_time,
    )


def _make_segment(
    row: _RawDOE,
    start: datetime,
    end: datetime,
    *,
    observed_at: datetime | None = None,
) -> _KnownControlSegment:
    return _KnownControlSegment(
        row=row,
        site_control_group_id=row.site_control_group_id,
        primacy=1,
        observed_at=observed_at if observed_at is not None else start,
        effective_start=start,
        effective_end=end,
        step_name="",
    )


def _obs(*offsets_seconds: int) -> list[_Observation]:
    return [_Observation(T0 + timedelta(seconds=s)) for s in offsets_seconds]


_GROUPS = {1: _RawControlGroup(site_control_group_id=1, primacy=1)}


# ─── _build_control_versions / _version_at ────────────────────────────────────


def test_build_control_versions_update_chain():
    """An archived (updated) row holds the values until its archive_time; the active row after."""
    t_update = T0 + timedelta(seconds=300)
    old = _make_doe_row(1, 1, T0, 900, export_limit=5000.0, is_archive=True, archive_time=t_update)
    new = _make_doe_row(1, 1, T0, 900, export_limit=2000.0)

    versions = _build_control_versions([new, old])[1]

    assert len(versions) == 2
    assert versions[0].row is old
    assert versions[0].valid_from == T0
    assert versions[0].valid_to == t_update
    assert versions[1].row is new
    assert versions[1].valid_from == t_update
    assert versions[1].valid_to == _FAR_FUTURE


def test_build_control_versions_deletion_terminates_chain():
    """A deleted row's values are valid until deleted_time; afterwards the DOE does not exist."""
    t_cancel = T0 + timedelta(seconds=240)
    deleted = _make_doe_row(1, 1, T0, 900, is_archive=True, deleted_time=t_cancel)

    versions = _build_control_versions([deleted])[1]

    assert len(versions) == 1
    assert versions[0].valid_to == t_cancel
    assert _version_at(versions, t_cancel - timedelta(seconds=1)) is versions[0]
    assert _version_at(versions, t_cancel) is None
    assert _version_at(versions, T0 - timedelta(seconds=1)) is None  # before creation


@pytest.mark.parametrize("reverse_row_order", [False, True])
def test_build_control_versions_same_instant_update_and_delete(reverse_row_order):
    """A DOE updated and deleted at the same instant (one transaction) resolves deterministically:
    the pre-update values hold until the shared boundary, then the DOE ceases to exist."""
    t_boundary = T0 + timedelta(seconds=300)
    update_snapshot = _make_doe_row(1, 1, T0, 900, export_limit=5000.0, is_archive=True, archive_time=t_boundary)
    delete_snapshot = _make_doe_row(1, 1, T0, 900, export_limit=2000.0, is_archive=True, deleted_time=t_boundary)
    rows = [delete_snapshot, update_snapshot] if reverse_row_order else [update_snapshot, delete_snapshot]

    versions = _build_control_versions(rows)[1]

    assert len(versions) == 1
    assert versions[0].row is update_snapshot
    assert versions[0].valid_to == t_boundary
    assert _version_at(versions, t_boundary) is None  # deletion terminates the chain


def test_build_control_versions_superseded_window_omitted():
    """A window in which the server presented the DOE as superseded yields no live version."""
    t_supersede = T0 + timedelta(seconds=300)
    old_pre = _make_doe_row(1, 1, T0, 900, export_limit=5000.0, is_archive=True, archive_time=t_supersede)
    old_post = _make_doe_row(1, 1, T0, 900, export_limit=5000.0, superseded=True)

    versions = _build_control_versions([old_post, old_pre])[1]

    assert len(versions) == 1
    assert versions[0].row is old_pre
    assert _version_at(versions, t_supersede) is None


# ─── _replay_control_knowledge ────────────────────────────────────────────────


def test_replay_cancellation_observed_at_next_poll():
    """ALL-28 case: a cancelled control remains the client's active control until the first
    poll AFTER the deletion — not until the deletion itself, nor the next control's receipt."""
    t_cancel = T0 + timedelta(seconds=240)
    doe = _make_doe_row(3, 1, T0, 900, is_archive=True, deleted_time=t_cancel)
    observations = {1: _obs(30, 90, 150, 210, 270, 330)}

    segments = _replay_control_knowledge([doe], observations, _GROUPS, {}, T0 - timedelta(minutes=5))

    assert len(segments) == 1
    ctrl = segments[0]
    assert ctrl.observed_at == T0 + timedelta(seconds=30)
    assert ctrl.effective_start == T0 + timedelta(seconds=30)
    # Deleted at T+240s; the poll at T+270s is when the client finds out
    assert ctrl.effective_end == T0 + timedelta(seconds=270)


def test_replay_cancellation_never_reobserved_runs_full_course():
    """If the client never polls again after a cancellation, it executes the known schedule."""
    t_cancel = T0 + timedelta(seconds=240)
    doe = _make_doe_row(3, 1, T0, 900, is_archive=True, deleted_time=t_cancel)
    observations = {1: _obs(30)}  # single poll, before the cancellation

    segments = _replay_control_knowledge([doe], observations, _GROUPS, {}, T0 - timedelta(minutes=5))

    assert len(segments) == 1
    assert segments[0].effective_end == T0 + timedelta(seconds=900)


def test_replay_value_update_observed_at_next_poll():
    """A server-side value update only takes effect for the client at its next poll."""
    t_update = T0 + timedelta(seconds=300)
    old = _make_doe_row(1, 1, T0, 900, export_limit=5000.0, is_archive=True, archive_time=t_update)
    new = _make_doe_row(1, 1, T0, 900, export_limit=2000.0)
    observations = {1: _obs(30, 400)}

    segments = _replay_control_knowledge([new, old], observations, _GROUPS, {}, T0 - timedelta(minutes=5))

    assert len(segments) == 2
    first, second = sorted(segments, key=lambda c: c.effective_start)
    # Client follows the OLD values until the poll at T+400s reveals the update
    assert first.row is old
    assert first.effective_start == T0 + timedelta(seconds=30)
    assert first.effective_end == T0 + timedelta(seconds=400)
    assert second.row is new
    assert second.effective_start == T0 + timedelta(seconds=400)
    assert second.effective_end == T0 + timedelta(seconds=900)
    # Each version records the observation that revealed it
    assert first.observed_at == T0 + timedelta(seconds=30)
    assert second.observed_at == T0 + timedelta(seconds=400)


def test_replay_never_observed_control_excluded():
    """A control created after the client's last poll contributes nothing."""
    doe = _make_doe_row(1, 1, T0 + timedelta(seconds=500), 900, created=T0 + timedelta(seconds=500))
    observations = {1: _obs(30, 90)}  # both polls before creation

    segments = _replay_control_knowledge([doe], observations, _GROUPS, {}, T0 - timedelta(minutes=5))

    assert segments == []


def test_replay_superseded_at_first_observation_excluded():
    """A control that was already superseded when first observed is never followed."""
    doe = _make_doe_row(1, 1, T0, 900, superseded=True)
    observations = {1: _obs(30, 90)}

    segments = _replay_control_knowledge([doe], observations, _GROUPS, {}, T0 - timedelta(minutes=5))

    assert segments == []


def test_replay_supersession_observed_at_next_poll():
    """The old control is followed until the poll that reveals its supersession; the
    replacement is followed from that same poll."""
    t_supersede = T0 + timedelta(seconds=300)
    old_pre = _make_doe_row(1, 1, T0, 900, export_limit=5000.0, is_archive=True, archive_time=t_supersede)
    old_post = _make_doe_row(1, 1, T0, 900, export_limit=5000.0, superseded=True)
    replacement = _make_doe_row(2, 1, t_supersede, 600, created=t_supersede, export_limit=1000.0)
    observations = {1: _obs(30, 400)}

    segments = _replay_control_knowledge(
        [old_post, old_pre, replacement], observations, _GROUPS, {}, T0 - timedelta(minutes=5)
    )

    by_id = {c.row.dynamic_operating_envelope_id: c for c in segments}
    assert set(by_id) == {1, 2}
    assert by_id[1].effective_end == T0 + timedelta(seconds=400)
    assert by_id[2].effective_start == T0 + timedelta(seconds=400)


def test_replay_scheduled_start_honoured_without_a_poll():
    """The client executes a known future schedule on time — no poll needed at start_time."""
    start = T0 + timedelta(seconds=600)
    doe = _make_doe_row(1, 1, start, 300, created=T0 + timedelta(seconds=10))
    observations = {1: _obs(30)}  # only poll is well before start_time

    segments = _replay_control_knowledge([doe], observations, _GROUPS, {}, T0 - timedelta(minutes=5))

    assert len(segments) == 1
    assert segments[0].effective_start == start
    assert segments[0].effective_end == start + timedelta(seconds=300)


def test_replay_control_created_before_test_start_excluded():
    doe = _make_doe_row(1, 1, T0, 900)
    observations = {1: _obs(30)}

    segments = _replay_control_knowledge([doe], observations, _GROUPS, {}, T0 + timedelta(minutes=5))

    assert segments == []


# ─── _replay_default_knowledge ────────────────────────────────────────────────


def test_replay_default_change_observed_at_next_poll():
    """A changed default only becomes the client's known default at its next dderc poll."""
    t_change = T0 + timedelta(seconds=300)
    old = _make_default_row(1, T0 - timedelta(seconds=60), export_limit=0.0, is_archive=True, archive_time=t_change)
    new = _make_default_row(1, t_change, export_limit=0.0, grad_w=100)
    observations = {1: _obs(30, 400)}

    known = _replay_default_knowledge([new, old], observations)[1]

    assert len(known) == 2
    assert known[0].row is old
    assert known[0].known_from == T0 + timedelta(seconds=30)
    assert known[0].known_until == T0 + timedelta(seconds=400)
    assert known[1].row is new
    assert known[1].known_from == T0 + timedelta(seconds=400)
    assert known[1].known_until == _FAR_FUTURE


def test_replay_default_unchanged_across_polls_merges():
    default = _make_default_row(1, T0 - timedelta(seconds=60), export_limit=8000.0)
    observations = {1: _obs(30, 90, 150)}

    known = _replay_default_knowledge([default], observations)[1]

    assert len(known) == 1
    assert known[0].known_from == T0 + timedelta(seconds=30)
    assert known[0].known_until == _FAR_FUTURE


def test_replay_default_unknown_before_first_poll():
    default = _make_default_row(1, T0 - timedelta(seconds=60), export_limit=8000.0)
    observations = {1: _obs(120)}

    known = _replay_default_knowledge([default], observations)[1]

    assert len(known) == 1
    assert known[0].known_from == T0 + timedelta(seconds=120)


def test_replay_default_no_observations_yields_nothing():
    default = _make_default_row(1, T0, export_limit=8000.0)

    known = _replay_default_knowledge([default], {})[1]

    assert known == []


def test_replay_deleted_default_uses_deleted_time():
    """A deleted default's server validity ends at deleted_time (authoritative), even when the
    audit archive_time disagrees."""
    t_delete = T0 + timedelta(seconds=300)
    deleted = _make_default_row(
        1,
        T0 - timedelta(seconds=60),
        export_limit=0.0,
        is_archive=True,
        deleted_time=t_delete,
        archive_time=t_delete + timedelta(seconds=5),
    )
    observations = {1: _obs(30, 400)}

    known = _replay_default_knowledge([deleted], observations)[1]

    assert len(known) == 1
    assert known[0].known_from == T0 + timedelta(seconds=30)
    # The poll at T+400s reveals the deletion; no further known default
    assert known[0].known_until == T0 + timedelta(seconds=400)


# ─── _collect_poll_observations / _build_group_observations ───────────────────


def _req(path: str, when: datetime, *, method: HTTPMethod = HTTPMethod.GET, status: HTTPStatus = HTTPStatus.OK):
    return RequestEntry(
        url=f"https://envoy.example.com{path}",
        path=path,
        method=method,
        status=status,
        timestamp=when,
        step_name="STEP-1",
        body_xml_errors=[],
        request_id=1,
    )


def test_collect_poll_observations_separates_derc_and_dderc():
    reqs = [
        _req("/edev/1/derp/1/derc", T0),
        _req("/edev/1/derp/1/dderc", T0 + timedelta(seconds=10)),
        _req("/edev/1/derp/2/derc", T0 + timedelta(seconds=20)),
    ]
    history = _collect_poll_observations(reqs)
    assert [o.time for o in history.derc[1]] == [T0]
    assert [o.time for o in history.dderc[1]] == [T0 + timedelta(seconds=10)]
    assert [o.time for o in history.derc[2]] == [T0 + timedelta(seconds=20)]
    assert history.derc[1][0].step_name == "STEP-1"


def test_collect_poll_observations_ignores_failures_and_non_gets():
    reqs = [
        _req("/edev/1/derp/1/derc", T0, status=HTTPStatus.INTERNAL_SERVER_ERROR),
        _req("/edev/1/derp/1/derc", T0 + timedelta(seconds=10), method=HTTPMethod.PUT),
        _req("/edev/1/derp/1/derc", T0 + timedelta(seconds=20)),
    ]
    history = _collect_poll_observations(reqs)
    assert [o.time for o in history.derc[1]] == [T0 + timedelta(seconds=20)]
    # The failed GET still proves the client was polling this group's list
    assert history.derc_attempted == {1}


def test_collect_poll_observations_ignores_single_control_gets():
    """A GET of one DERControl (/derc/{id}) is not a list observation — it cannot reveal
    list-level additions, cancellations or supersessions. Query strings still match."""
    reqs = [
        _req("/edev/1/derp/1/derc/5", T0),
        _req("/edev/1/derp/1/derc?l=10&s=0", T0 + timedelta(seconds=10)),
    ]
    history = _collect_poll_observations(reqs)
    assert [o.time for o in history.derc[1]] == [T0 + timedelta(seconds=10)]
    assert history.derc_attempted == {1}


def test_build_group_observations_no_polls_no_subscription_errors():
    """A group with DOEs but no poll attempts and no subscription cannot be modelled."""
    doe = _make_doe_row(1, 1, T0, 900)

    with pytest.raises(ValueError, match="never polled"):
        _build_group_observations([doe], [], [], set(), set())


def test_build_group_observations_all_failed_polls_give_no_knowledge(caplog):
    """Failed polls prove the client was polling (no error) but grant it no knowledge."""
    doe = _make_doe_row(1, 1, T0, 900)
    failed_polls = [
        _req("/edev/1/derp/1/derc", T0 + timedelta(seconds=k * 60), status=HTTPStatus.FORBIDDEN) for k in range(3)
    ]

    derc_obs, _ = _build_group_observations([doe], [], failed_polls, set(), set())

    assert derc_obs[1] == []
    assert any("failed" in r.message for r in caplog.records)


def test_build_group_observations_subscribed_merges_polls_and_changes():
    """A subscribed group observes every server-side change AND its own polls."""
    doe = _make_doe_row(1, 1, T0, 900)
    polls = [_req("/edev/1/derp/1/derc", T0 + timedelta(seconds=50))]

    derc_obs, _ = _build_group_observations([doe], [], polls, {1}, set())

    assert [o.time for o in derc_obs[1]] == [T0, T0 + timedelta(seconds=50)]


# ─── _compute_disconnect_intervals ────────────────────────────────────────────


def test_disconnect_split_segments_no_spurious_reconnect():
    """A disconnect control updated mid-flight splits into two knowledge segments; the split
    must not fabricate a reconnect (and its 60s grace) at the segment boundary."""
    t_split = T0 + timedelta(seconds=300)
    t_expire = T0 + timedelta(seconds=600)
    test_end = T0 + timedelta(seconds=1200)
    row_v1 = _make_doe_row(1, 1, T0, 600, set_connected=False, is_archive=True, archive_time=t_split)
    row_v2 = _make_doe_row(1, 1, T0, 600, set_connected=False)
    segments = [
        _make_segment(row_v1, T0, t_split),
        _make_segment(row_v2, t_split, t_expire),
    ]

    intervals = _compute_disconnect_intervals(segments, test_end)

    # One continuous disconnection: expiry at T+600s + 60s grace
    assert intervals == [(T0, t_expire + timedelta(seconds=60))]


def test_disconnect_distinct_does_still_reconnect():
    """Two separate disconnect controls produce two intervals with a reconnect between them."""
    test_end = T0 + timedelta(seconds=2000)
    row_a = _make_doe_row(1, 1, T0, 300, set_connected=False)
    row_b = _make_doe_row(2, 1, T0 + timedelta(seconds=900), 300, set_connected=False)
    segments = [
        _make_segment(row_a, T0, T0 + timedelta(seconds=300)),
        _make_segment(row_b, T0 + timedelta(seconds=900), T0 + timedelta(seconds=1200)),
    ]

    intervals = _compute_disconnect_intervals(segments, test_end)

    assert intervals == [
        (T0, T0 + timedelta(seconds=360)),
        (T0 + timedelta(seconds=900), T0 + timedelta(seconds=1260)),
    ]


# ─── Per-type limit resolution ────────────────────────────────────────────────


def test_overlapping_field_disjoint_controls_do_not_mask():
    """A newer live control that does not set export must not release an older overlapping
    control's export limit (envoy keeps field-disjoint overlapping controls live)."""
    t = T0 + timedelta(seconds=100)
    older = _make_doe_row(1, 1, T0, 900, export_limit=5000.0)
    newer = _make_doe_row(2, 1, T0 + timedelta(seconds=50), 900, export_limit=None, set_connected=True)
    segments_by_group = {
        1: [
            _make_segment(older, T0, T0 + timedelta(seconds=900)),
            _make_segment(newer, T0 + timedelta(seconds=50), T0 + timedelta(seconds=950)),
        ]
    }

    val, src = _get_effective_upper_at(t, [_GROUPS[1]], segments_by_group, {})

    assert val == pytest.approx(5000.0)
    assert src is segments_by_group[1][0]


# ─── _build_receipt_markers ───────────────────────────────────────────────────


def test_receipt_marker_at_update_reveal():
    """The poll that reveals a server-side value update gets its own receipt marker."""
    t_update = T0 + timedelta(seconds=300)
    old = _make_doe_row(1, 1, T0, 900, export_limit=5000.0, is_archive=True, archive_time=t_update)
    new = _make_doe_row(1, 1, T0, 900, export_limit=2000.0)
    observations = {1: _obs(30, 400)}
    segments = _replay_control_knowledge([new, old], observations, _GROUPS, {}, T0 - timedelta(minutes=5))

    markers = _build_receipt_markers(segments, set())

    assert [m.time for m in markers] == [T0 + timedelta(seconds=30), T0 + timedelta(seconds=400)]
    assert all(not m.is_subscribed for m in markers)
