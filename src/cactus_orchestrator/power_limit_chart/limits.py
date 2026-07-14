"""Effective limit resolution, ramp physics and trace building.

Limits are derived from the client's known control segments across all DERPrograms
(resolved by primacy), with known defaults as fallback. Transitions are rendered as linear
ramps using rampTms (DERControl), DefaultDERControl setGradW, or AS4777 wGra as appropriate.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from cactus_orchestrator.power_limit_chart.db import _RawControlGroup, _RawDefault
from cactus_orchestrator.power_limit_chart.replay import _Known, _KnownControlSegment

# AS4777.2 wGra: 16.67%/min = 0.2778%/s = 27.78 hundredths-of-%-per-sec
_AS4777_WGRA_HUNDREDTHS: float = 16.67 / 60.0 * 100.0

# AS4777 soft-start: fixed 15-second ramp
_AS4777_SOFT_RAMP_SECONDS: float = 15.0

# Grace period after opModConnect:true before returning to normal control
_OP_MOD_CONNECT_GRACE_SECONDS: float = 60.0

# Post-reconnect window during which AS4777 wGra applies regardless of rampTms/setGradW
_POST_DISCONNECT_WGRA_SECONDS: float = 6 * 60.0

_KnownDefault = _Known[_RawDefault]
_LimitSource = _KnownControlSegment | _KnownDefault

_SegmentsByGroup = dict[int, list[_KnownControlSegment]]
_DefaultsByGroup = dict[int, list[_KnownDefault]]


@dataclass
class _LimitEvent:
    """A moment where the target power limit changes."""

    time: datetime
    target: float  # Watts (positive = export ceiling, negative = import floor)
    source: _LimitSource | None  # None = unconstrained
    instant: bool = False  # True for disconnect/energise boundaries (ramp = 0s)


@dataclass
class _ReceiptMarker:
    """Records when the device received (a version of) a DERControl."""

    time: datetime
    group_id: int
    is_subscribed: bool  # True = notification delivered; False = polled
    step_name: str  # step active at receipt time (empty string if unknown)


def _fmt_video_time(seconds: float) -> str:
    """Format a seconds offset as a video timestamp: 'M:SS' or 'H:MM:SS'."""
    s = int(max(0, seconds))
    hh = s // 3600
    mm = (s % 3600) // 60
    ss = s % 60
    if hh > 0:
        return f"{hh}:{mm:02d}:{ss:02d}"
    return f"{mm}:{ss:02d}"


# ─── Point-in-time resolution ─────────────────────────────────────────────────


def _controls_live_at(t: datetime, group_segments: list[_KnownControlSegment]) -> list[_KnownControlSegment]:
    return [s for s in group_segments if s.effective_start <= t < s.effective_end]


def _newest_control(candidates: list[_KnownControlSegment]) -> _KnownControlSegment:
    """Most recently created wins (sep2 client-side supersession); ties broken by id."""
    return max(candidates, key=lambda s: (s.row.created_time, s.row.dynamic_operating_envelope_id))


def _find_active_default_at(t: datetime, group_id: int, defaults_by_group: _DefaultsByGroup) -> _KnownDefault | None:
    """Find the default control the client knew about for the given group at time t."""
    for d in defaults_by_group.get(group_id, []):
        if d.known_from <= t < d.known_until:
            return d
    return None


def _resolve_type_limit(
    t: datetime,
    sorted_groups: list[_RawControlGroup],
    segments_by_group: _SegmentsByGroup,
    defaults_by_group: _DefaultsByGroup,
    get_ctrl_val: Callable[[_KnownControlSegment], float | None],
    get_default_val: Callable[[_KnownDefault], float | None],
) -> tuple[float | None, _LimitSource | None]:
    """Resolve the effective limit for a single control type independently.

    Phase 1 — active controls in primacy order: the first group with a live control that
    sets this type wins; among live controls setting the type, the newest wins. Live controls
    that do NOT set the type do not mask an older overlapping control that does (envoy keeps
    field-disjoint overlapping controls live).
    Phase 2 — defaults in primacy order: the first group whose known default sets this type wins.
    Phase 3 — unconstrained: returns (None, None)."""
    for group in sorted_groups:
        live = _controls_live_at(t, segments_by_group.get(group.site_control_group_id, []))
        typed = [s for s in live if get_ctrl_val(s) is not None]
        if typed:
            winner = _newest_control(typed)
            return get_ctrl_val(winner), winner

    for group in sorted_groups:
        default = _find_active_default_at(t, group.site_control_group_id, defaults_by_group)
        if default is not None:
            val = get_default_val(default)
            if val is not None:
                return val, default

    return None, None


def _get_effective_upper_at(
    t: datetime,
    sorted_groups: list[_RawControlGroup],
    segments_by_group: _SegmentsByGroup,
    defaults_by_group: _DefaultsByGroup,
) -> tuple[float | None, _LimitSource | None]:
    """Returns (effective_limit_watts, source) for the upper bound at time t.

    Export and generation limits are each resolved independently (active controls →
    defaults → unconstrained) and then combined with min so the most restrictive
    applies. The source returned is that of the binding (minimum) type."""
    exp_val, exp_src = _resolve_type_limit(
        t,
        sorted_groups,
        segments_by_group,
        defaults_by_group,
        lambda c: c.row.export_limit_watts,
        lambda d: d.row.export_limit_active_watts,
    )
    gen_val, gen_src = _resolve_type_limit(
        t,
        sorted_groups,
        segments_by_group,
        defaults_by_group,
        lambda c: c.row.generation_limit_active_watts,
        lambda d: d.row.generation_limit_active_watts,
    )
    stor_val, stor_src = _resolve_type_limit(
        t,
        sorted_groups,
        segments_by_group,
        defaults_by_group,
        lambda c: _positive_or_none(c.row.storage_target_active_watts),
        lambda d: _positive_or_none(d.row.storage_target_active_watts),
    )
    candidates = [(v, s) for v, s in [(exp_val, exp_src), (gen_val, gen_src), (stor_val, stor_src)] if v is not None]
    if not candidates:
        return None, None
    return min(candidates, key=lambda x: x[0])


def _get_effective_lower_at(
    t: datetime,
    sorted_groups: list[_RawControlGroup],
    segments_by_group: _SegmentsByGroup,
    defaults_by_group: _DefaultsByGroup,
) -> tuple[float | None, _LimitSource | None]:
    """Returns (effective_limit_watts, source) for the lower bound at time t.
    Returns a positive magnitude value — caller negates it for display.

    Import and load limits are each resolved independently (active controls →
    defaults → unconstrained) and then combined with min so the most restrictive
    applies. The source returned is that of the binding (minimum) type."""
    imp_val, imp_src = _resolve_type_limit(
        t,
        sorted_groups,
        segments_by_group,
        defaults_by_group,
        lambda c: c.row.import_limit_active_watts,
        lambda d: d.row.import_limit_active_watts,
    )
    load_val, load_src = _resolve_type_limit(
        t,
        sorted_groups,
        segments_by_group,
        defaults_by_group,
        lambda c: c.row.load_limit_active_watts,
        lambda d: d.row.load_limit_active_watts,
    )
    stor_val, stor_src = _resolve_type_limit(
        t,
        sorted_groups,
        segments_by_group,
        defaults_by_group,
        lambda c: _negative_magnitude_or_none(c.row.storage_target_active_watts),
        lambda d: _negative_magnitude_or_none(d.row.storage_target_active_watts),
    )
    candidates = [(v, s) for v, s in [(imp_val, imp_src), (load_val, load_src), (stor_val, stor_src)] if v is not None]
    if not candidates:
        return None, None
    return min(candidates, key=lambda x: x[0])


def _positive_or_none(value: float | None) -> float | None:
    return value if value is not None and value > 0 else None


def _negative_magnitude_or_none(value: float | None) -> float | None:
    return abs(value) if value is not None and value < 0 else None


# ─── Disconnect / opModConnect tracking ───────────────────────────────────────


def _connect_polarity(segment: _KnownControlSegment) -> bool | None:
    """False = forces disconnection, True = commands reconnection, None = neither."""
    if segment.row.set_connected is False or segment.row.set_energized is False:
        return False
    if segment.row.set_connected is True or segment.row.set_energized is True:
        return True
    return None


def _connect_windows(segments: list[_KnownControlSegment]) -> list[tuple[bool, datetime, datetime]]:
    """Per-DOE (polarity, start, end) connect/disconnect windows.

    Adjacent same-polarity segments of one DOE (a value update revealed mid-flight) are merged
    so the segment split does not fabricate a reconnect."""
    by_doe: dict[int, list[tuple[bool, _KnownControlSegment]]] = {}
    for seg in segments:
        polarity = _connect_polarity(seg)
        if polarity is not None:
            by_doe.setdefault(seg.row.dynamic_operating_envelope_id, []).append((polarity, seg))

    windows: list[tuple[bool, datetime, datetime]] = []
    for doe_segments in by_doe.values():
        doe_segments.sort(key=lambda p: p[1].effective_start)
        merged: list[tuple[bool, datetime, datetime]] = []
        for polarity, seg in doe_segments:
            if merged and merged[-1][0] == polarity and merged[-1][2] >= seg.effective_start:
                merged[-1] = (polarity, merged[-1][1], max(merged[-1][2], seg.effective_end))
            else:
                merged.append((polarity, seg.effective_start, seg.effective_end))
        windows.extend(merged)
    return windows


def _compute_disconnect_intervals(
    segments: list[_KnownControlSegment],
    test_end: datetime,
) -> list[tuple[datetime, datetime]]:
    """Returns intervals during which the device active power is forced to 0,
    including the 1-minute grace period after reconnect.

    Reconnection is triggered by either:
    - An opModConnect=True active control (at its effective_start), or
    - The opModConnect=False control expiring (at its effective_end)."""
    connected_events: list[tuple[datetime, bool]] = []
    for polarity, start, end in _connect_windows(segments):
        if polarity is False:
            connected_events.append((start, False))
            connected_events.append((end, True))  # expiry = reconnect
        else:
            connected_events.append((start, True))
    connected_events.sort(key=lambda e: e[0])

    disconnect_intervals: list[tuple[datetime, datetime]] = []
    for i, (t, connected) in enumerate(connected_events):
        if connected:
            continue
        reconnect_time: datetime | None = None
        for j in range(i + 1, len(connected_events)):
            if connected_events[j][1]:
                reconnect_time = connected_events[j][0]
                break
        if reconnect_time is None:
            disconnect_end = test_end
        else:
            disconnect_end = min(reconnect_time + timedelta(seconds=_OP_MOD_CONNECT_GRACE_SECONDS), test_end)
        disconnect_intervals.append((t, disconnect_end))

    return disconnect_intervals


# ─── Timeline sweep ───────────────────────────────────────────────────────────


def _collect_event_times(
    segments: list[_KnownControlSegment],
    defaults_by_group: _DefaultsByGroup,
    disconnect_intervals: list[tuple[datetime, datetime]],
    test_start: datetime,
    test_end: datetime,
) -> list[datetime]:
    """Collect all times at which the effective limit might change."""
    times: set[datetime] = {test_start, test_end}
    for seg in segments:
        times.add(seg.effective_start)
        times.add(seg.effective_end)
    for defaults in defaults_by_group.values():
        for d in defaults:
            if test_start < d.known_from < test_end:
                times.add(d.known_from)
            if test_start < d.known_until < test_end:
                times.add(d.known_until)
    for ds, de in disconnect_intervals:
        if test_start <= ds <= test_end:
            times.add(ds)
        if test_start <= de <= test_end:
            times.add(de)
    return sorted(t for t in times if test_start <= t <= test_end)


def _controller_band_at(
    t: datetime,
    sorted_groups: list[_RawControlGroup],
    segments_by_group: _SegmentsByGroup,
    defaults_by_group: _DefaultsByGroup,
) -> tuple[tuple | None, str]:
    """(key, label) of the effective controller at time t: the highest-priority live DOE,
    else the highest-priority known default, else (None, "")."""
    for group in sorted_groups:
        live = _controls_live_at(t, segments_by_group.get(group.site_control_group_id, []))
        if live:
            winner = _newest_control(live)
            doe_id = winner.row.dynamic_operating_envelope_id
            return ("doe", doe_id), winner.step_name or f"Grp{winner.site_control_group_id} DOE#{doe_id}"
    for group in sorted_groups:
        gid = group.site_control_group_id
        if _find_active_default_at(t, gid, defaults_by_group) is not None:
            return ("default", gid), f"Default-DERP{gid}"
    return None, ""


def _sweep_timeline(
    event_times: list[datetime],
    sorted_groups: list[_RawControlGroup],
    segments_by_group: _SegmentsByGroup,
    defaults_by_group: _DefaultsByGroup,
    disconnect_intervals: list[tuple[datetime, datetime]],
    upper_max_w: float,
    lower_max_w: float,
    test_end: datetime,
) -> tuple[list[_LimitEvent], list[_LimitEvent], list[tuple[str, datetime, datetime]]]:
    """Single pass over the event timeline producing (upper_events, lower_events, step_intervals).

    step_intervals are (label, start, end) windows showing the effective controller at each
    moment: the highest-priority live DOE (labelled by step name, falling back to
    'Grp{gid} DOE#{id}'), else the highest-priority known default ('Default-DERP{gid}').
    Periods with neither are omitted."""
    upper_events: list[_LimitEvent] = []
    lower_events: list[_LimitEvent] = []
    prev_upper: float | None = None
    prev_lower: float | None = None
    disconnect_starts = {ds for ds, _ in disconnect_intervals}

    # Each band segment is (key, label, start) where key uniquely identifies the controller.
    band_segments: list[tuple[tuple | None, str, datetime]] = []
    last_key: tuple | None = ()  # sentinel — not a valid key

    for t in event_times:
        is_disconnected = any(ds <= t < de for ds, de in disconnect_intervals)
        instant = t in disconnect_starts

        upper_source: _LimitSource | None
        lower_source: _LimitSource | None
        if is_disconnected:
            upper_target, upper_source = 0.0, None
            lower_target, lower_source = 0.0, None
        else:
            # Control values above the device maximum are NOT cropped — the trace shows the
            # commanded limit, with the region beyond device capability indicated in the render.
            raw, upper_source = _get_effective_upper_at(t, sorted_groups, segments_by_group, defaults_by_group)
            upper_target = raw if raw is not None else upper_max_w
            raw, lower_source = _get_effective_lower_at(t, sorted_groups, segments_by_group, defaults_by_group)
            lower_target = -raw if raw is not None else -lower_max_w

        if prev_upper is None or abs(upper_target - prev_upper) > 0.1:
            upper_events.append(_LimitEvent(time=t, target=upper_target, source=upper_source, instant=instant))
            prev_upper = upper_target
        if prev_lower is None or abs(lower_target - prev_lower) > 0.1:
            lower_events.append(_LimitEvent(time=t, target=lower_target, source=lower_source, instant=instant))
            prev_lower = lower_target

        # Controller band (independent of disconnection, matching the limit traces' sources)
        key, label = _controller_band_at(t, sorted_groups, segments_by_group, defaults_by_group)
        if key != last_key:
            band_segments.append((key, label, t))
            last_key = key

    step_intervals: list[tuple[str, datetime, datetime]] = []
    for i, (key, label, seg_start) in enumerate(band_segments):
        if key is None:
            continue
        seg_end = band_segments[i + 1][2] if i + 1 < len(band_segments) else test_end
        step_intervals.append((label, seg_start, seg_end))

    return upper_events, lower_events, step_intervals


# ─── Ramp duration computation ────────────────────────────────────────────────


def _rate_based_duration(grad_w_hundredths: float, delta_w: float, set_max_w: float) -> float:
    """Compute ramp duration from a grad_w rate (hundredths of %/s of setMaxW)."""
    rate_w_per_sec = (grad_w_hundredths / 10000.0) * set_max_w
    if rate_w_per_sec <= 0.0:
        return 0.0
    return delta_w / rate_w_per_sec


def _compute_ramp(
    source: _LimitSource | None,
    at_time: datetime,
    delta_w: float,
    set_max_w: float,
    defaults_by_group: _DefaultsByGroup,
) -> tuple[float, str]:
    """Compute ramp duration and description for a transition to source.

    Rules:
      To DER control:    rampTms → DefaultDERControl.setGradW → 15s fixed
      To default:        DefaultDERControl.setGradW → AS4777 wGra rate
      To unconstrained:  AS4777 wGra rate
    """
    if isinstance(source, _KnownControlSegment):
        ramp_t = source.row.ramp_time_seconds
        if ramp_t is not None and ramp_t > 0.0:
            return ramp_t, f"rampTms={ramp_t:.0f}s"
        active_default = _find_active_default_at(at_time, source.site_control_group_id, defaults_by_group)
        default_grad = active_default.row.ramp_rate_percent_per_second if active_default is not None else None
        if default_grad is not None and default_grad > 0:
            secs = _rate_based_duration(float(default_grad), delta_w, set_max_w)
            return secs, f"Default setGradW={default_grad} ({secs:.0f}s)"
        return _AS4777_SOFT_RAMP_SECONDS, "AS4777 soft-start (15s)"

    if source is not None:
        default_grad = source.row.ramp_rate_percent_per_second
        if default_grad is not None and default_grad > 0:
            secs = _rate_based_duration(float(default_grad), delta_w, set_max_w)
            return secs, f"Default setGradW={default_grad} ({secs:.0f}s)"
        secs = _rate_based_duration(_AS4777_WGRA_HUNDREDTHS, delta_w, set_max_w)
        return secs, f"AS4777 wGra ({secs:.0f}s)"

    # Unconstrained
    secs = _rate_based_duration(_AS4777_WGRA_HUNDREDTHS, delta_w, set_max_w)
    return secs, f"AS4777 wGra ({secs:.0f}s)"


# ─── Trace building ───────────────────────────────────────────────────────────


def _build_trace(  # noqa: C901
    limit_events: list[_LimitEvent],
    test_start: datetime,
    test_end: datetime,
    initial_value: float,
    set_max_w: float,
    disconnect_intervals: list[tuple[datetime, datetime]],
    defaults_by_group: _DefaultsByGroup,
    video_offset_seconds: float = 0.0,
) -> list[tuple[datetime, float, str]]:
    """Convert limit events into a piecewise-linear trace with ramps.

    Returns a list of (time, watts, hover_text) tuples. hover_text is non-empty only
    at ramp-start points and describes the ramp rule applied (e.g. 'rampTms=120s').
    """
    post_reconnect_windows = [
        (de, de + timedelta(seconds=_POST_DISCONNECT_WGRA_SECONDS)) for _, de in disconnect_intervals
    ]
    points: list[tuple[datetime, float, str]] = [(test_start, initial_value, f"{initial_value:.0f} W")]

    # Track the current ramp: from (ramp_start_t, ramp_start_v) to (ramp_end_t, ramp_end_v)
    ramp_start_t = test_start
    ramp_start_v = initial_value
    ramp_end_t = test_start
    ramp_end_v = initial_value

    # Deferred ramp endpoint: only flushed to points once we know no event interrupts it.
    # Stored as (time, value); None when there is no pending endpoint.
    pending_ramp_end: tuple[datetime, float] | None = None

    for ev in limit_events:
        if ev.time <= test_start:
            continue
        if ev.time > test_end:
            break

        # Flush the pending ramp endpoint if the ramp completes before this event.
        # If the event arrives before the ramp end, drop the endpoint — the ramp was
        # interrupted and should not continue past the interruption point.
        if pending_ramp_end is not None:
            if pending_ramp_end[0] <= ev.time:
                points.append((pending_ramp_end[0], pending_ramp_end[1], f"{pending_ramp_end[1]:.0f} W"))
            pending_ramp_end = None

        # Determine the current value at ev.time (accounting for any active ramp)
        ramp_duration_secs = (ramp_end_t - ramp_start_t).total_seconds()
        if ramp_duration_secs <= 0.0 or ev.time >= ramp_end_t:
            current_v = ramp_end_v
        else:
            frac = (ev.time - ramp_start_t).total_seconds() / ramp_duration_secs
            frac = max(0.0, min(1.0, frac))
            current_v = ramp_start_v + frac * (ramp_end_v - ramp_start_v)

        if abs(ev.target - current_v) < 0.1:
            continue

        delta_w = abs(ev.target - current_v)
        if ev.instant:
            ramp_secs = 0.0
            desc = "instant (disconnect)"
        elif any(ws <= ev.time < we for ws, we in post_reconnect_windows):
            ramp_secs = _rate_based_duration(_AS4777_WGRA_HUNDREDTHS, delta_w, set_max_w)
            desc = f"AS4777 wGra post-reconnect ({ramp_secs:.0f}s)"
        else:
            ramp_secs, desc = _compute_ramp(ev.source, ev.time, delta_w, set_max_w, defaults_by_group)
        rel_secs = (ev.time - test_start).total_seconds() + video_offset_seconds
        if isinstance(ev.source, _KnownControlSegment):
            ctrl_label = ev.source.label
        elif ev.source is not None:
            ctrl_label = f"Default DERP{ev.source.row.site_control_group_id}"
        else:
            ctrl_label = "No active limit"
        hover = (
            f"Control received: {ctrl_label}<br>"
            f"Relative time: {_fmt_video_time(rel_secs)}<br>"
            f"Ramping from {current_v:.0f} W to {ev.target:.0f} W<br>"
            f"Ramp rate: {desc}"
        )

        points.append((ev.time, current_v, hover))

        ramp_end_dt = ev.time + timedelta(seconds=ramp_secs)
        if ramp_end_dt <= test_end:
            # Defer the endpoint — a later event may interrupt this ramp.
            pending_ramp_end = (ramp_end_dt, ev.target)
        # If ramp_end_dt > test_end, don't append test_end here — subsequent events
        # within the test window would then be inserted AFTER the test_end point,
        # causing plotly to draw a backward line. The post-loop section below handles
        # the clipped test_end value correctly once all events have been processed.

        ramp_start_t = ev.time
        ramp_start_v = current_v
        ramp_end_t = ramp_end_dt
        ramp_end_v = ev.target

    # Flush any pending ramp endpoint that was not interrupted by a later event.
    if pending_ramp_end is not None:
        points.append((pending_ramp_end[0], pending_ramp_end[1], f"{pending_ramp_end[1]:.0f} W"))

    # Ensure the trace reaches test_end
    if points[-1][0] < test_end:
        ramp_duration_secs = (ramp_end_t - ramp_start_t).total_seconds()
        if ramp_duration_secs <= 0.0 or test_end >= ramp_end_t:
            v_final = ramp_end_v
        else:
            frac = (test_end - ramp_start_t).total_seconds() / ramp_duration_secs
            v_final = ramp_start_v + frac * (ramp_end_v - ramp_start_v)
        points.append((test_end, v_final, f"{v_final:.0f} W"))

    return points


# ─── Receipt markers ──────────────────────────────────────────────────────────


def _build_receipt_markers(
    segments: list[_KnownControlSegment],
    subscribed_group_ids: set[int],
) -> list[_ReceiptMarker]:
    """One marker per unique (group, revealing observation) pair — the initial receipt of each
    control plus any later observation that revealed a server-side value update."""
    seen: set[tuple[int, datetime]] = set()
    markers: list[_ReceiptMarker] = []
    for seg in segments:
        key = (seg.site_control_group_id, seg.observed_at)
        if key not in seen:
            seen.add(key)
            markers.append(
                _ReceiptMarker(
                    time=seg.observed_at,
                    group_id=seg.site_control_group_id,
                    is_subscribed=seg.site_control_group_id in subscribed_group_ids,
                    step_name=seg.step_name,
                )
            )
    return sorted(markers, key=lambda m: m.time)
