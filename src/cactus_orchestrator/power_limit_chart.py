"""
Generates a standalone HTML chart of expected device active power limits
throughout a test run.

The chart shows two traces:
  - Upper bound: effective export / generation limit (positive watts)
  - Lower bound: effective import / load limit (shown as negative watts)

Limits are derived from DERControls across all DERPrograms (resolved by primacy),
with default controls as fallback. Transitions are rendered as linear ramps using
rampTms (DERControl), DefaultDERControl setGradW, or AS4777 wGra as appropriate.

Receipt timing:
  - Subscribed programs: device receives controls at created_time (notifications assumed delivered).
  - Polled programs: device receives the control at the first observed GET to the DERControl
    list endpoint for that program after the control's created_time. Falls back to
    the control's start_time if no poll is found.
"""

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

import plotly.graph_objects as go  # type: ignore[import-untyped]
from cactus_runner.app.envoy_common import (
    get_active_site,
    get_site_control_group_defaults_with_archive,
    get_site_controls_active_archived,
)
from cactus_schema.runner.schema import RequestEntry
from envoy.server.model.archive.doe import (
    ArchiveDynamicOperatingEnvelope,
    ArchiveSiteControlGroupDefault,
)
from envoy.server.model.doe import (
    DynamicOperatingEnvelope,
    SiteControlGroup,
    SiteControlGroupDefault,
)
from envoy.server.model.site import SiteDERSetting
from envoy.server.model.subscription import Subscription, SubscriptionResource
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# AS4777.2 wGra: 16.67%/min = 0.2778%/s = 27.78 hundredths-of-%-per-sec
_AS4777_WGRA_HUNDREDTHS: float = 16.67 / 60.0 * 100.0

# AS4777 soft-start: fixed 15-second ramp
_AS4777_SOFT_RAMP_SECONDS: float = 15.0

# Grace period after opModConnect:true before returning to normal control
_OP_MOD_CONNECT_GRACE_SECONDS: float = 60.0

# Post-reconnect window during which AS4777 wGra applies regardless of rampTms/setGradW
_POST_DISCONNECT_WGRA_SECONDS: float = 6 * 60.0

# Matches /edev/{n}/derp/{group_id}/derc (with optional query string)
_DERC_PATH_RE = re.compile(r"/edev/\d+/derp/(\d+)/derc")

# Type alias for default control models (active or archived)
_DefaultLike = SiteControlGroupDefault | ArchiveSiteControlGroupDefault

# Cycling colour palette for step-name bands (semi-transparent fills)
_STEP_PALETTE = [
    "rgba(130,179,255,0.45)",
    "rgba(130,220,170,0.45)",
    "rgba(255,210,120,0.45)",
    "rgba(255,140,170,0.45)",
    "rgba(200,140,255,0.45)",
    "rgba(120,220,220,0.45)",
]


# ─── Internal data types ──────────────────────────────────────────────────────


@dataclass
class _EnrichedControl:
    """DERControl with receipt time and effective window pre-computed."""

    doe: DynamicOperatingEnvelope | ArchiveDynamicOperatingEnvelope
    site_control_group_id: int
    primacy: int
    receipt_time: datetime
    effective_start: datetime  # max(doe.start_time, receipt_time)
    effective_end: datetime
    step_name: str  # step active when the device received this control

    @property
    def export_limit(self) -> float | None:
        v = self.doe.export_limit_watts
        return float(v) if v is not None else None

    @property
    def gen_limit(self) -> float | None:
        v = self.doe.generation_limit_active_watts
        return float(v) if v is not None else None

    @property
    def import_limit(self) -> float | None:
        v = self.doe.import_limit_active_watts
        return float(v) if v is not None else None

    @property
    def load_limit(self) -> float | None:
        v = self.doe.load_limit_active_watts
        return float(v) if v is not None else None

    @property
    def set_connected(self) -> bool | None:
        return self.doe.set_connected

    @property
    def set_energized(self) -> bool | None:
        return self.doe.set_energized

    @property
    def ramp_time_seconds(self) -> float | None:
        v = self.doe.ramp_time_seconds
        return float(v) if v is not None else None


@dataclass
class _LimitEvent:
    """A moment where the target power limit changes."""

    time: datetime
    target: float  # Watts (positive = export ceiling, negative = import floor)
    source: object | None  # _EnrichedControl | _DefaultLike | None (unconstrained)
    instant: bool = False  # True for disconnect/energise boundaries (ramp = 0s)


@dataclass
class _ReceiptMarker:
    """Records when the device received a DERControl."""

    time: datetime
    group_id: int
    is_subscribed: bool  # True = notification delivered; False = polled
    step_name: str  # step active at receipt time (empty string if unknown)


# ─── DB queries ───────────────────────────────────────────────────────────────


async def _get_der_setting(session: AsyncSession) -> SiteDERSetting | None:
    site = await get_active_site(session, include_der_settings=True)
    if site is None:
        return None
    for der in site.site_ders:
        if der.site_der_setting is not None:
            return der.site_der_setting
    return None


async def _get_control_groups(session: AsyncSession) -> list[SiteControlGroup]:
    result = await session.execute(select(SiteControlGroup))
    return list(result.scalars().all())


async def _get_subscribed_group_ids(session: AsyncSession) -> set[int]:
    """Returns site_control_group_ids for which an active DERControl subscription exists.
    Only subscriptions with an explicit resource_id are considered; 0 subscriptions is valid
    (device relies entirely on polling)."""
    result = await session.execute(
        select(Subscription).where(
            Subscription.resource_type == SubscriptionResource.DYNAMIC_OPERATING_ENVELOPE,
            Subscription.resource_id.is_not(None),
        )
    )
    return {sub.resource_id for sub in result.scalars().all() if sub.resource_id is not None}


# ─── Control-interval and receipt-marker helpers ──────────────────────────────


def _compute_active_control_intervals(
    event_times: list[datetime],
    sorted_groups: list[SiteControlGroup],
    enriched: list[_EnrichedControl],
    defaults_by_group: dict[int, list[_DefaultLike]],
    test_end: datetime,
) -> list[tuple[str, datetime, datetime]]:
    """Return (label, start, end) intervals showing the effective controller at each moment.

    Active DOEs are labelled with the step name at receipt (falling back to 'Grp{gid} DOE#{id}').
    When no DOE is active, the highest-priority active default is labelled 'Default-DERP{gid}'.
    Periods with neither are omitted."""
    # Each segment is (key, label, start) where key uniquely identifies the active entity.
    segments: list[tuple[tuple | None, str, datetime]] = []
    last_key: tuple | None = ()  # sentinel — not a valid key

    for T in event_times:
        # Find highest-priority active DOE across all groups
        winning_doe: _EnrichedControl | None = None
        for group in sorted_groups:
            ctrl = _find_active_control_at(T, group.site_control_group_id, enriched)
            if ctrl is not None:
                winning_doe = ctrl
                break

        # If no DOE, find highest-priority active default
        winning_default_gid: int | None = None
        if winning_doe is None:
            for group in sorted_groups:
                if _find_active_default_at(T, group.site_control_group_id, defaults_by_group) is not None:
                    winning_default_gid = group.site_control_group_id
                    break

        if winning_doe is not None:
            doe_id = winning_doe.doe.dynamic_operating_envelope_id
            key: tuple | None = ("doe", doe_id)
            label = winning_doe.step_name or f"Grp{winning_doe.site_control_group_id} DOE#{doe_id}"
        elif winning_default_gid is not None:
            key = ("default", winning_default_gid)
            label = f"Default-DERP{winning_default_gid}"
        else:
            key = None
            label = ""

        if key != last_key:
            segments.append((key, label, T))
            last_key = key

    intervals: list[tuple[str, datetime, datetime]] = []
    for i, (key, label, seg_start) in enumerate(segments):
        if key is None:
            continue
        seg_end = segments[i + 1][2] if i + 1 < len(segments) else test_end
        intervals.append((label, seg_start, seg_end))
    return intervals


def _build_receipt_markers(
    enriched: list[_EnrichedControl],
    subscribed_group_ids: set[int],
) -> list[_ReceiptMarker]:
    """One marker per unique (group, receipt_time) pair in enriched controls."""
    seen: set[tuple[int, datetime]] = set()
    markers: list[_ReceiptMarker] = []
    for ctrl in enriched:
        key = (ctrl.site_control_group_id, ctrl.receipt_time)
        if key not in seen:
            seen.add(key)
            markers.append(
                _ReceiptMarker(
                    time=ctrl.receipt_time,
                    group_id=ctrl.site_control_group_id,
                    is_subscribed=ctrl.site_control_group_id in subscribed_group_ids,
                    step_name=ctrl.step_name,
                )
            )
    return sorted(markers, key=lambda m: m.time)


# ─── Receipt time computation ─────────────────────────────────────────────────


def _compute_receipt_time_and_step(
    doe: DynamicOperatingEnvelope | ArchiveDynamicOperatingEnvelope,
    group_id: int,
    subscribed_group_ids: set[int],
    sorted_requests: list[RequestEntry],
) -> tuple[datetime, str]:
    """Returns (receipt_time, step_name) for this control.

    For subscribed groups: receipt is created_time; step_name is the last non-empty
    step seen in requests to /edev/*/derp/{group_id}/derc at or before created_time.
    For polled groups: receipt is the first GET to /edev/*/derp/{group_id}/derc after
    created_time; step_name comes from that request. Fallback: (doe.start_time, "").
    """
    if group_id in subscribed_group_ids:
        step = ""
        for req in sorted_requests:
            if req.timestamp > doe.created_time:
                break
            m = _DERC_PATH_RE.search(req.path)
            if m and int(m.group(1)) == group_id:
                name = (req.step_name or "").strip()
                if name:
                    step = name
        return doe.created_time, step

    for req in sorted_requests:
        if req.timestamp <= doe.created_time:
            continue
        if req.method != "GET":
            continue
        m = _DERC_PATH_RE.search(req.path)
        if m and int(m.group(1)) == group_id:
            return req.timestamp, (req.step_name or "").strip()

    logger.debug(
        "power_limit_chart: no DERControl poll found for group %d after %r; falling back to start_time",
        group_id,
        doe.created_time,
    )
    return doe.start_time, ""


# ─── Control enrichment ───────────────────────────────────────────────────────


def _effective_end_for_doe(
    doe: DynamicOperatingEnvelope | ArchiveDynamicOperatingEnvelope,
) -> datetime | None:
    """Returns the effective end time for a DOE, or None if no valid window exists."""
    base_end = doe.start_time + timedelta(seconds=doe.duration_seconds)
    if isinstance(doe, ArchiveDynamicOperatingEnvelope):
        if doe.deleted_time is not None and doe.deleted_time > doe.start_time:
            return min(base_end, doe.deleted_time)
        if doe.archive_time is not None and doe.archive_time > doe.start_time:
            return min(base_end, doe.archive_time)
        return None
    return base_end


def _build_enriched_controls(
    all_does: list[DynamicOperatingEnvelope | ArchiveDynamicOperatingEnvelope],
    test_start: datetime,
    groups_by_id: dict[int, SiteControlGroup],
    subscribed_group_ids: set[int],
    request_history: list[RequestEntry],
    doe_tags: dict[int, str],
) -> list[_EnrichedControl]:
    sorted_requests = sorted(request_history, key=lambda r: r.timestamp)
    enriched: list[_EnrichedControl] = []
    for doe in all_does:
        # Skip superseded controls. Active DOEs: their effective history is in archive.
        # Archive DOEs with superseded=True are mass-delete snapshots — their validity
        # window is already covered by the earlier superseded=False archive for the same DOE.
        if doe.superseded:
            continue

        # Only include controls created during the test
        if doe.created_time < test_start:
            continue

        effective_end = _effective_end_for_doe(doe)
        if effective_end is None:
            continue

        group = groups_by_id.get(doe.site_control_group_id)
        if group is None:
            continue

        receipt, inferred_step = _compute_receipt_time_and_step(
            doe, doe.site_control_group_id, subscribed_group_ids, sorted_requests
        )
        # Prefer the tag recorded at control-creation time; fall back to the step name
        # inferred from request timestamps (less reliable when creation occurs during
        # the same request that polls the DERC list).
        step_name = doe_tags.get(doe.dynamic_operating_envelope_id, inferred_step)
        effective_start = max(doe.start_time, receipt)

        if effective_start >= effective_end:
            continue

        enriched.append(
            _EnrichedControl(
                doe=doe,
                site_control_group_id=doe.site_control_group_id,
                primacy=group.primacy,
                receipt_time=receipt,
                effective_start=effective_start,
                effective_end=effective_end,
                step_name=step_name,
            )
        )
    return enriched


# ─── Default control helpers ──────────────────────────────────────────────────


def _default_active_window(d: _DefaultLike) -> tuple[datetime, datetime] | None:
    """Returns the (start, end) time window during which this default was active.
    Returns None if the archive_time is missing (should not happen; silently ignored)."""
    if isinstance(d, ArchiveSiteControlGroupDefault):
        if d.archive_time is None:
            return None
        return d.changed_time, d.archive_time
    # Active default: valid from changed_time to the far future
    far_future = datetime(9999, 1, 1, tzinfo=d.changed_time.tzinfo)
    return d.changed_time, far_future


def _build_defaults_by_group(all_defaults: list[_DefaultLike]) -> dict[int, list[_DefaultLike]]:
    result: dict[int, list[_DefaultLike]] = {}
    for d in all_defaults:
        result.setdefault(d.site_control_group_id, []).append(d)
    return result


# ─── Disconnect / opModConnect tracking ───────────────────────────────────────


def _compute_disconnect_intervals(
    enriched: list[_EnrichedControl],
    test_end: datetime,
) -> list[tuple[datetime, datetime]]:
    """Returns intervals during which the device active power is forced to 0,
    including the 1-minute grace period after reconnect.

    Reconnection is triggered by either:
    - An opModConnect=True active control (at its effective_start), or
    - The opModConnect=False control expiring (at its effective_end).
    """
    # False controls (set_connected=False OR set_energized=False) contribute two events:
    # disconnect at effective_start, reconnect at effective_end.
    # True controls contribute one event: reconnect at effective_start.
    connected_events: list[tuple[datetime, bool]] = []
    for ctrl in enriched:
        if ctrl.set_connected is False or ctrl.set_energized is False:
            connected_events.append((ctrl.effective_start, False))
            connected_events.append((ctrl.effective_end, True))  # expiry = reconnect
        elif ctrl.set_connected is True or ctrl.set_energized is True:
            connected_events.append((ctrl.effective_start, True))
    connected_events.sort(key=lambda e: e[0])

    disconnect_intervals: list[tuple[datetime, datetime]] = []
    i = 0
    while i < len(connected_events):
        t, connected = connected_events[i]
        if not connected:
            disconnect_start = t
            reconnect_time: datetime | None = None
            for j in range(i + 1, len(connected_events)):
                if connected_events[j][1]:
                    reconnect_time = connected_events[j][0]
                    break
            if reconnect_time is None:
                disconnect_end = test_end
            else:
                disconnect_end = min(reconnect_time + timedelta(seconds=_OP_MOD_CONNECT_GRACE_SECONDS), test_end)
            disconnect_intervals.append((disconnect_start, disconnect_end))
        i += 1

    return disconnect_intervals


# ─── Effective limit computation ──────────────────────────────────────────────


def _find_active_control_at(
    T: datetime,
    group_id: int,
    enriched: list[_EnrichedControl],
) -> _EnrichedControl | None:
    """Find the highest-priority active enriched control for the given group at time T."""
    best: _EnrichedControl | None = None
    for ctrl in enriched:
        if ctrl.site_control_group_id != group_id:
            continue
        if not (ctrl.effective_start <= T < ctrl.effective_end):
            continue
        if best is None:
            best = ctrl
        # Archive records take priority over active (they represent confirmed historical windows)
        elif isinstance(ctrl.doe, ArchiveDynamicOperatingEnvelope) and not isinstance(
            best.doe, ArchiveDynamicOperatingEnvelope
        ):
            best = ctrl
    return best


def _find_active_default_at(
    T: datetime,
    group_id: int,
    defaults_by_group: dict[int, list[_DefaultLike]],
) -> _DefaultLike | None:
    """Find the active default control for the given group at time T."""
    for d in defaults_by_group.get(group_id, []):
        window = _default_active_window(d)
        if window is None:
            continue
        start, end = window
        if start <= T < end:
            return d
    return None


def _resolve_type_limit(
    T: datetime,
    sorted_groups: list[SiteControlGroup],
    enriched: list[_EnrichedControl],
    defaults_by_group: dict[int, list[_DefaultLike]],
    get_ctrl_val: Callable[[_EnrichedControl], float | None],
    get_default_val: Callable[[_DefaultLike], float | None],
) -> tuple[float | None, object | None]:
    """Resolve the effective limit for a single control type independently.

    Phase 1 — active controls in primacy order: the first group whose active control
    sets this type wins.
    Phase 2 — defaults in primacy order: the first group whose active default sets
    this type wins.
    Phase 3 — unconstrained: returns (None, None).

    Keeping the two phases separate means an active control that does not set a
    particular type does not shadow a default that does."""
    for group in sorted_groups:
        ctrl = _find_active_control_at(T, group.site_control_group_id, enriched)
        if ctrl is not None:
            val = get_ctrl_val(ctrl)
            if val is not None:
                return val, ctrl

    for group in sorted_groups:
        default = _find_active_default_at(T, group.site_control_group_id, defaults_by_group)
        if default is not None:
            val = get_default_val(default)
            if val is not None:
                return val, default

    return None, None


def _get_effective_upper_at(
    T: datetime,
    sorted_groups: list[SiteControlGroup],
    enriched: list[_EnrichedControl],
    defaults_by_group: dict[int, list[_DefaultLike]],
) -> tuple[float | None, object | None]:
    """Returns (effective_limit_watts, source) for the upper bound at time T.

    Export and generation limits are each resolved independently (active controls →
    defaults → unconstrained) and then combined with min so the most restrictive
    applies. The source returned is that of the binding (minimum) type."""
    exp_val, exp_src = _resolve_type_limit(
        T,
        sorted_groups,
        enriched,
        defaults_by_group,
        lambda c: c.export_limit,
        lambda d: float(d.export_limit_active_watts) if d.export_limit_active_watts is not None else None,
    )
    gen_val, gen_src = _resolve_type_limit(
        T,
        sorted_groups,
        enriched,
        defaults_by_group,
        lambda c: c.gen_limit,
        lambda d: float(d.generation_limit_active_watts) if d.generation_limit_active_watts is not None else None,
    )
    if exp_val is not None and gen_val is not None:
        return (exp_val, exp_src) if exp_val <= gen_val else (gen_val, gen_src)
    if exp_val is not None:
        return exp_val, exp_src
    if gen_val is not None:
        return gen_val, gen_src
    return None, None


def _get_effective_lower_at(
    T: datetime,
    sorted_groups: list[SiteControlGroup],
    enriched: list[_EnrichedControl],
    defaults_by_group: dict[int, list[_DefaultLike]],
) -> tuple[float | None, object | None]:
    """Returns (effective_limit_watts, source) for the lower bound at time T.
    Returns a positive magnitude value — caller negates it for display.

    Import and load limits are each resolved independently (active controls →
    defaults → unconstrained) and then combined with min so the most restrictive
    applies. The source returned is that of the binding (minimum) type."""
    imp_val, imp_src = _resolve_type_limit(
        T,
        sorted_groups,
        enriched,
        defaults_by_group,
        lambda c: c.import_limit,
        lambda d: float(d.import_limit_active_watts) if d.import_limit_active_watts is not None else None,
    )
    load_val, load_src = _resolve_type_limit(
        T,
        sorted_groups,
        enriched,
        defaults_by_group,
        lambda c: c.load_limit,
        lambda d: float(d.load_limit_active_watts) if d.load_limit_active_watts is not None else None,
    )
    if imp_val is not None and load_val is not None:
        return (imp_val, imp_src) if imp_val <= load_val else (load_val, load_src)
    if imp_val is not None:
        return imp_val, imp_src
    if load_val is not None:
        return load_val, load_src
    return None, None


# ─── Ramp duration computation ────────────────────────────────────────────────


def _rate_based_duration(grad_w_hundredths: float, delta_w: float, set_max_w: float) -> float:
    """Compute ramp duration from a grad_w rate (hundredths of %/s of setMaxW)."""
    rate_w_per_sec = (grad_w_hundredths / 10000.0) * set_max_w
    if rate_w_per_sec <= 0.0:
        return 0.0
    return delta_w / rate_w_per_sec


def _compute_ramp(
    source: object | None,
    at_time: datetime,
    delta_w: float,
    set_max_w: float,
    defaults_by_group: dict[int, list[_DefaultLike]],
) -> tuple[float, str]:
    """Compute ramp duration and description for a transition to source.

    Rules:
      To DER control:    rampTms → DefaultDERControl.setGradW → 15s fixed
      To default:        DefaultDERControl.setGradW → AS4777 wGra rate
      To unconstrained:  AS4777 wGra rate
    """
    if isinstance(source, _EnrichedControl):
        ramp_t = source.ramp_time_seconds
        if ramp_t is not None and ramp_t > 0.0:
            return ramp_t, f"rampTms={ramp_t:.0f}s"
        active_default = _find_active_default_at(at_time, source.site_control_group_id, defaults_by_group)
        default_grad = getattr(active_default, "ramp_rate_percent_per_second", None)
        if default_grad is not None and default_grad > 0:
            secs = _rate_based_duration(float(default_grad), delta_w, set_max_w)
            return secs, f"Default setGradW={default_grad} ({secs:.0f}s)"
        return _AS4777_SOFT_RAMP_SECONDS, "AS4777 soft-start (15s)"

    if source is not None:
        default_grad = getattr(source, "ramp_rate_percent_per_second", None)
        if default_grad is not None and default_grad > 0:
            secs = _rate_based_duration(float(default_grad), delta_w, set_max_w)
            return secs, f"Default setGradW={default_grad} ({secs:.0f}s)"
        secs = _rate_based_duration(_AS4777_WGRA_HUNDREDTHS, delta_w, set_max_w)
        return secs, f"AS4777 wGra ({secs:.0f}s)"

    # Unconstrained
    secs = _rate_based_duration(_AS4777_WGRA_HUNDREDTHS, delta_w, set_max_w)
    return secs, f"AS4777 wGra ({secs:.0f}s)"


# ─── Event collection ─────────────────────────────────────────────────────────


def _collect_event_times(
    enriched: list[_EnrichedControl],
    defaults_by_group: dict[int, list[_DefaultLike]],
    disconnect_intervals: list[tuple[datetime, datetime]],
    test_start: datetime,
    test_end: datetime,
) -> list[datetime]:
    """Collect all times at which the effective limit might change."""
    times: set[datetime] = {test_start, test_end}
    for ctrl in enriched:
        times.add(ctrl.effective_start)
        times.add(ctrl.effective_end)
    for defaults in defaults_by_group.values():
        for d in defaults:
            window = _default_active_window(d)
            if window is None:
                continue
            start, end = window
            if test_start < start < test_end:
                times.add(start)
            if test_start < end < test_end:
                times.add(end)
    for ds, de in disconnect_intervals:
        if test_start <= ds <= test_end:
            times.add(ds)
        if test_start <= de <= test_end:
            times.add(de)
    return sorted(t for t in times if test_start <= t <= test_end)


def _build_limit_events(
    is_upper: bool,
    event_times: list[datetime],
    sorted_groups: list[SiteControlGroup],
    enriched: list[_EnrichedControl],
    defaults_by_group: dict[int, list[_DefaultLike]],
    disconnect_intervals: list[tuple[datetime, datetime]],
    set_max_w: float,
) -> list[_LimitEvent]:
    """Build list of limit target changes over the test timeline."""
    events: list[_LimitEvent] = []
    prev_target: float | None = None
    disconnect_starts = {ds for ds, _ in disconnect_intervals}

    for T in event_times:
        is_disconnected = any(ds <= T < de for ds, de in disconnect_intervals)

        if is_disconnected:
            target = 0.0
            source = None
        elif is_upper:
            raw, source = _get_effective_upper_at(T, sorted_groups, enriched, defaults_by_group)
            target = min(raw if raw is not None else set_max_w, set_max_w)
        else:
            raw, source = _get_effective_lower_at(T, sorted_groups, enriched, defaults_by_group)
            target = max(-(raw if raw is not None else set_max_w), -set_max_w)

        if prev_target is None or abs(target - prev_target) > 0.1:
            instant = T in disconnect_starts
            events.append(_LimitEvent(time=T, target=target, source=source, instant=instant))
            prev_target = target

    return events


# ─── Trace building ───────────────────────────────────────────────────────────


def _build_trace(
    limit_events: list[_LimitEvent],
    test_start: datetime,
    test_end: datetime,
    initial_value: float,
    set_max_w: float,
    disconnect_intervals: list[tuple[datetime, datetime]],
    defaults_by_group: dict[int, list[_DefaultLike]],
) -> list[tuple[datetime, float, str]]:
    """Convert limit events into a piecewise-linear trace with ramps.

    Returns a list of (time, watts, hover_text) tuples. hover_text is non-empty only
    at ramp-start points and describes the ramp rule applied (e.g. 'rampTms=120s').
    """
    post_reconnect_windows = [
        (de, de + timedelta(seconds=_POST_DISCONNECT_WGRA_SECONDS)) for _, de in disconnect_intervals
    ]
    points: list[tuple[datetime, float, str]] = [(test_start, initial_value, "")]

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
                points.append((pending_ramp_end[0], pending_ramp_end[1], ""))
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
        rel_time = _duration_label((ev.time - test_start).total_seconds())
        hover = f"<br>T+{rel_time}  →  {ev.target:.0f} W  ({desc})"

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
        points.append((pending_ramp_end[0], pending_ramp_end[1], ""))

    # Ensure the trace reaches test_end
    if points[-1][0] < test_end:
        ramp_duration_secs = (ramp_end_t - ramp_start_t).total_seconds()
        if ramp_duration_secs <= 0.0 or test_end >= ramp_end_t:
            v_final = ramp_end_v
        else:
            frac = (test_end - ramp_start_t).total_seconds() / ramp_duration_secs
            v_final = ramp_start_v + frac * (ramp_end_v - ramp_start_v)
        points.append((test_end, v_final, ""))

    return points


# ─── Chart rendering ──────────────────────────────────────────────────────────


def _duration_label(seconds: float) -> str:
    """Convert a seconds offset to a compact label: '30s', '5m', '1h2m'."""
    s = int(abs(seconds))
    if s < 60:
        return f"{s}s"
    mins = s // 60
    secs = s % 60
    if mins < 60:
        return f"{mins}m" if secs == 0 else f"{mins}m{secs}s"
    hours = mins // 60
    rem = mins % 60
    return f"{hours}h{rem}m" if rem else f"{hours}h"


def _fmt_video_time(seconds: float) -> str:
    """Format a seconds offset as a video timestamp: 'M:SS' or 'H:MM:SS'."""
    s = int(max(0, seconds))
    hh = s // 3600
    mm = (s % 3600) // 60
    ss = s % 60
    if hh > 0:
        return f"{hh}:{mm:02d}:{ss:02d}"
    return f"{mm}:{ss:02d}"


def _choose_tick_interval_seconds(duration_secs: float) -> int:
    """Pick a sensible tick interval so there are roughly 8-20 ticks."""
    for interval in [60, 120, 300, 600, 900, 1800, 3600, 7200]:
        if duration_secs / interval <= 20:
            return interval
    return 3600


def _assign_completion_lanes(
    completions: list[tuple[str, datetime]], to_rel: Callable[[datetime], float], duration_secs: float
) -> list[int]:
    """Assign a vertical stack lane (0, 1, 2, …) to each step completion.

    Lane 0 is closest to the plot; higher lanes stack further above it.
    A new lane is opened whenever all existing lanes have a label within
    min_gap_secs, so any number of simultaneous completions stack cleanly.
    The gap scales with duration so labels don't overlap on long tests.
    """
    # ~22 chars at font size 8 occupies roughly 1/8 of the ~700px plot width.
    min_gap_secs = max(45.0, duration_secs / 8)
    last_in_lane: list[float] = []  # most-recent rel-time assigned to each lane
    lanes: list[int] = []
    for _, t in completions:
        rel = to_rel(t)
        # Find the lowest lane with enough horizontal clearance; open a new one if none.
        assigned = len(last_in_lane)
        for k, last in enumerate(last_in_lane):
            if rel - last >= min_gap_secs:
                assigned = k
                break
        if assigned == len(last_in_lane):
            last_in_lane.append(rel)
        else:
            last_in_lane[assigned] = rel
        lanes.append(assigned)
    return lanes


def _add_receipt_markers(
    fig: go.Figure,
    receipt_markers: list[_ReceiptMarker],
    to_rel: Callable[[datetime], float],
    set_max_w: float,
) -> None:
    for m in receipt_markers:
        color = "#27ae60" if m.is_subscribed else "#e67e22"
        fig.add_shape(
            type="line",
            xref="x",
            yref="paper",
            x0=to_rel(m.time),
            x1=to_rel(m.time),
            y0=0.02,
            y1=0.98,
            line=dict(color=color, width=1.5, dash="dot"),
            opacity=0.55,
        )
    if any(m.is_subscribed for m in receipt_markers):
        fig.add_trace(
            go.Scatter(
                x=[None],
                y=[None],
                mode="lines",
                line=dict(color="#27ae60", width=1.5, dash="dot"),
                name="Notif receipt",
            )
        )
    if any(not m.is_subscribed for m in receipt_markers):
        fig.add_trace(
            go.Scatter(
                x=[None], y=[None], mode="lines", line=dict(color="#e67e22", width=1.5, dash="dot"), name="Poll receipt"
            )
        )
    if receipt_markers:
        fig.add_trace(
            go.Scatter(
                x=[to_rel(m.time) for m in receipt_markers],
                y=[set_max_w * 0.55] * len(receipt_markers),
                mode="markers",
                marker=dict(
                    symbol="triangle-down",
                    size=9,
                    color=["#27ae60" if m.is_subscribed else "#e67e22" for m in receipt_markers],
                    opacity=0.85,
                ),
                customdata=[
                    ["Notification" if m.is_subscribed else "Poll", m.step_name or f"Group {m.group_id}"]
                    for m in receipt_markers
                ],
                hovertemplate="%{customdata[0]} receipt — %{customdata[1]}<extra>Receipt</extra>",
                showlegend=False,
            )
        )


def _add_reconnect_markers(
    fig: go.Figure,
    disconnect_intervals: list[tuple[datetime, datetime]],
    to_rel: Callable[[datetime], float],
    duration_secs: float,
) -> None:
    _COLOR = "rgba(120,120,120,0.5)"
    reconnect_rels = [
        to_rel(de - timedelta(seconds=_OP_MOD_CONNECT_GRACE_SECONDS))
        for _, de in disconnect_intervals
        if to_rel(de - timedelta(seconds=_OP_MOD_CONNECT_GRACE_SECONDS)) < duration_secs
    ]
    for rel in reconnect_rels:
        fig.add_shape(
            type="line",
            xref="x",
            yref="paper",
            x0=rel,
            x1=rel,
            y0=0,
            y1=1,
            line=dict(color=_COLOR, width=1, dash="dot"),
        )
    if reconnect_rels:
        fig.add_trace(
            go.Scatter(
                x=reconnect_rels,
                y=[0] * len(reconnect_rels),
                mode="markers",
                marker=dict(symbol="line-ns", size=10, color=_COLOR),
                customdata=[["60 s AS4777 wGra wait period on reconnection"]] * len(reconnect_rels),
                hovertemplate="Device reconnected — %{customdata[0]}<extra>Reconnect</extra>",
                showlegend=False,
            )
        )


def _add_completion_markers(
    fig: go.Figure,
    completions: list[tuple[str, datetime]],
    lanes: list[int],
    lane_y: list[float],
    duration_secs: float,
    to_rel: Callable[[datetime], float],
) -> None:
    _COMPLETION_COLOR = "#888"
    for (name, t), lane in zip(completions, lanes, strict=False):
        rel = to_rel(t)
        if rel < 0 or rel > duration_secs:
            continue
        fig.add_shape(
            type="line",
            xref="x",
            yref="paper",
            x0=rel,
            x1=rel,
            y0=0,
            y1=1,
            line=dict(color=_COMPLETION_COLOR, width=1.5, dash="dash"),
            opacity=0.45,
        )
        label = name if len(name) <= 22 else name[:20] + "…"
        fig.add_annotation(
            xref="x",
            yref="paper",
            x=rel,
            y=lane_y[lane],
            text=label,
            showarrow=True,
            arrowhead=0,
            arrowcolor=_COMPLETION_COLOR,
            arrowwidth=1,
            ax=0,
            ay=12,
            font=dict(size=8, color=_COMPLETION_COLOR),
            xanchor="center",
            yanchor="bottom",
        )
    fig.add_trace(
        go.Scatter(
            x=[None],
            y=[None],
            mode="lines",
            line=dict(color=_COMPLETION_COLOR, width=1.5, dash="dash"),
            name="Step complete",
        )
    )


def _add_step_strips(
    fig: go.Figure,
    step_intervals: list[tuple[str, datetime, datetime]],
    to_rel: Callable[[datetime], float],
    test_start: datetime,
    test_end: datetime,
) -> None:
    fig.add_annotation(
        xref="paper",
        yref="paper",
        x=-0.02,
        y=-0.32,
        text="<b>Controls</b>",
        showarrow=False,
        font=dict(size=9, color="#555"),
        xanchor="right",
        yanchor="middle",
    )
    palette_idx = 0
    for name, start, end in step_intervals:
        is_default = name.startswith("Default")
        if is_default:
            color = "rgba(180,180,180,0.45)"
        else:
            color = _STEP_PALETTE[palette_idx % len(_STEP_PALETTE)]
            palette_idx += 1
        x0 = to_rel(max(start, test_start))
        x1 = to_rel(min(end, test_end))
        if x1 <= x0:
            continue
        fig.add_shape(
            type="rect",
            xref="x",
            yref="paper",
            x0=x0,
            x1=x1,
            y0=-0.42,
            y1=-0.22,
            fillcolor=color,
            line=dict(color="rgba(0,0,0,0.18)", width=0.5),
            layer="below",
        )
        if x1 - x0 >= 20:
            label = name if len(name) <= 20 else name[:18] + "…"
            fig.add_annotation(
                xref="x",
                yref="paper",
                x=(x0 + x1) / 2,
                y=-0.32,
                text=label,
                showarrow=False,
                font=dict(size=8, color="#666" if is_default else "#000"),
                xanchor="center",
                yanchor="middle",
            )


def _render_html_chart(
    upper_trace: list[tuple[datetime, float, str]],
    lower_trace: list[tuple[datetime, float, str]],
    test_start: datetime,
    test_end: datetime,
    set_max_w: float,
    step_intervals: list[tuple[str, datetime, datetime]],
    receipt_markers: list[_ReceiptMarker],
    disconnect_intervals: list[tuple[datetime, datetime]],
    test_name: str = "",
    video_start_seconds: float | None = None,
    step_completions: list[tuple[str, datetime]] | None = None,
) -> str:
    duration_secs = (test_end - test_start).total_seconds()
    tick_interval = _choose_tick_interval_seconds(duration_secs)

    tick_vals: list[float] = []
    bottom_labels: list[str] = []

    t_secs = 0.0
    while t_secs <= duration_secs + 1:
        T = test_start + timedelta(seconds=t_secs)
        tick_vals.append(t_secs)
        rel_label = (
            _fmt_video_time(t_secs + video_start_seconds)
            if video_start_seconds is not None
            else _duration_label(t_secs)
        )
        bottom_labels.append(f"{rel_label}<br>{T.strftime('%H:%M')} UTC")
        t_secs += tick_interval

    def to_rel(t: datetime) -> float:
        return (t - test_start).total_seconds()

    y_max = set_max_w * 1.1
    y_min = -set_max_w * 1.1
    has_steps = bool(step_intervals)
    bottom_margin = 230 if has_steps else 130
    completions = sorted(step_completions or [], key=lambda x: x[1])
    lanes = _assign_completion_lanes(completions, to_rel, duration_secs) if completions else []
    max_lane = max(lanes) if lanes else 0
    # Each lane is 0.06 paper-coordinate units above the plot; legend floats above them all.
    lane_y = [1.06 + i * 0.06 for i in range(max_lane + 1)]
    legend_y = 1.06 + (max_lane + 1) * 0.06 + 0.06 if completions else 1.16
    top_margin = (140 + (max_lane + 1) * 30) if completions else 150
    height = top_margin + 350 + bottom_margin

    fig = go.Figure()

    # ── Main limit traces ────────────────────────────────────────────────────
    fig.add_trace(
        go.Scatter(
            x=[to_rel(t) for t, _, _ in upper_trace],
            y=[v for _, v, _ in upper_trace],
            mode="lines",
            name="Upper limit (Export / Gen)",
            line=dict(color="#e74c3c", width=2),
            customdata=[[h] for _, _, h in upper_trace],
            hovertemplate="%{y:.0f} W%{customdata[0]}<extra>Upper</extra>",
        )
    )
    fig.add_trace(
        go.Scatter(
            x=[to_rel(t) for t, _, _ in lower_trace],
            y=[v for _, v, _ in lower_trace],
            mode="lines",
            name="Lower limit (Import / Load)",
            line=dict(color="#3498db", width=2),
            customdata=[[h] for _, _, h in lower_trace],
            hovertemplate="%{y:.0f} W%{customdata[0]}<extra>Lower</extra>",
        )
    )

    # ── Reference lines ──────────────────────────────────────────────────────
    fig.add_hline(y=0, line_color="black", line_width=1, line_dash="dash", opacity=0.4)
    fig.add_hline(
        y=set_max_w,
        line_color="grey",
        line_width=1,
        line_dash="dot",
        annotation_text=f"setMaxW ({int(set_max_w)} W)",
        annotation_position="top right",
    )
    fig.add_hline(
        y=-set_max_w,
        line_color="grey",
        line_width=1,
        line_dash="dot",
        annotation_text=f"−setMaxW (−{int(set_max_w)} W)",
        annotation_position="bottom right",
    )

    # ── Overlays ─────────────────────────────────────────────────────────────
    _add_receipt_markers(fig, receipt_markers, to_rel, set_max_w)
    _add_reconnect_markers(fig, disconnect_intervals, to_rel, duration_secs)
    if completions:
        _add_completion_markers(fig, completions, lanes, lane_y, duration_secs, to_rel)
    if has_steps:
        _add_step_strips(fig, step_intervals, to_rel, test_start, test_end)

    # ── Layout ───────────────────────────────────────────────────────────────
    fig.update_layout(
        title=dict(text="Expected Device Power Limits", font=dict(size=16)),
        height=height,
        xaxis=dict(
            title="",
            tickmode="array",
            tickvals=tick_vals,
            ticktext=bottom_labels,
            range=[0, duration_secs],
            showgrid=True,
            gridcolor="rgba(0,0,0,0.08)",
        ),
        yaxis=dict(
            title="Active Power (W)",
            range=[y_min, y_max],
            showgrid=True,
            gridcolor="rgba(0,0,0,0.08)",
            zeroline=False,
        ),
        legend=dict(orientation="h", yanchor="bottom", y=legend_y, xanchor="right", x=1),
        plot_bgcolor="white",
        paper_bgcolor="white",
        margin=dict(t=top_margin, b=bottom_margin, l=80, r=120),
        hovermode="x unified",
        # ── Export / Import view toggle ──────────────────────────────────────
        updatemenus=[
            dict(
                type="buttons",
                direction="left",
                x=0.0,
                y=-0.12 if not has_steps else -0.50,
                xanchor="left",
                yanchor="top",
                buttons=[
                    dict(
                        label="Export view",
                        method="relayout",
                        args=[{"yaxis.range": [y_min, y_max], "yaxis.autorange": False}],
                    ),
                    dict(
                        label="Import view",
                        method="relayout",
                        args=[{"yaxis.range": [y_max, y_min], "yaxis.autorange": False}],
                    ),
                ],
                font=dict(size=11),
                bgcolor="white",
                bordercolor="#bbb",
                borderwidth=1,
            )
        ],
    )

    html = fig.to_html(full_html=True, include_plotlyjs=True)
    header = (
        '<div style="max-width:900px;margin:24px auto 0;padding:10px 14px 4px;font-family:sans-serif;">'
        f'<h2 style="margin:0 0 6px;font-size:20px;color:#222;">Device Power Chart: {test_name}</h2>'
        '<p style="margin:0;font-size:13px;color:#444;">'
        "This chart is an estimation of what device active power should look like during the witness test. "
        "It is based on active and default controls, polling and subscription timing, primacy, and expected "
        "ramp behaviour. It is intended to align with the TS5573 test definitions, but should not be used "
        "instead of these test procedures for client development."
        "</p>"
        "</div>"
    )
    return html.replace("<body>", "<body>" + header)


# ─── Public entry point ───────────────────────────────────────────────────────


async def generate_power_limit_chart_html(
    session: AsyncSession,
    test_start: datetime,
    test_end: datetime,
    request_history: list[RequestEntry],
    test_name: str = "",
    doe_tags: dict[int, str] | None = None,
    video_start_seconds: float | None = None,
    step_completions: list[tuple[str, datetime]] | None = None,
) -> str | None:
    """Generate a standalone HTML chart of expected device power limits.

    Returns None if the chart cannot be generated (e.g. DERSettings never sent,
    setMaxW is zero, or no SiteControlGroups exist).
    """
    der_setting = await _get_der_setting(session)
    if der_setting is None:
        logger.warning("power_limit_chart: no SiteDERSetting found - skipping chart")
        return None

    set_max_w = float(der_setting.max_w_value) * (10.0**der_setting.max_w_multiplier)
    if set_max_w <= 0.0:
        logger.warning("power_limit_chart: setMaxW <= 0 - skipping chart")
        return None

    control_groups = await _get_control_groups(session)
    if not control_groups:
        logger.warning("power_limit_chart: no SiteControlGroups found - skipping chart")
        return None
    groups_by_id = {g.site_control_group_id: g for g in control_groups}
    sorted_groups = sorted(control_groups, key=lambda g: g.primacy)

    all_does = await get_site_controls_active_archived(session)
    all_defaults = await get_site_control_group_defaults_with_archive(session)
    defaults_by_group = _build_defaults_by_group(all_defaults)

    subscribed_group_ids = await _get_subscribed_group_ids(session)

    enriched = _build_enriched_controls(
        all_does, test_start, groups_by_id, subscribed_group_ids, request_history, doe_tags or {}
    )

    disconnect_intervals = _compute_disconnect_intervals(enriched, test_end)

    event_times = _collect_event_times(enriched, defaults_by_group, disconnect_intervals, test_start, test_end)

    upper_events = _build_limit_events(
        True, event_times, sorted_groups, enriched, defaults_by_group, disconnect_intervals, set_max_w
    )
    lower_events = _build_limit_events(
        False, event_times, sorted_groups, enriched, defaults_by_group, disconnect_intervals, set_max_w
    )

    upper_trace = _build_trace(
        upper_events, test_start, test_end, set_max_w, set_max_w, disconnect_intervals, defaults_by_group
    )
    lower_trace = _build_trace(
        lower_events, test_start, test_end, -set_max_w, set_max_w, disconnect_intervals, defaults_by_group
    )

    step_intervals = _compute_active_control_intervals(
        event_times, sorted_groups, enriched, defaults_by_group, test_end
    )
    receipt_markers = _build_receipt_markers(enriched, subscribed_group_ids)

    return _render_html_chart(
        upper_trace,
        lower_trace,
        test_start,
        test_end,
        set_max_w,
        step_intervals,
        receipt_markers,
        disconnect_intervals,
        test_name=test_name,
        video_start_seconds=video_start_seconds,
        step_completions=step_completions or [],
    )
