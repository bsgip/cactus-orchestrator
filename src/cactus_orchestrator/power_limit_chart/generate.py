"""Public entry point: generates a standalone HTML chart of expected device active power
limits throughout a test run, from a restored envoy DB dump and the runner request history.

The chart shows two traces:
  - Upper bound: effective export / generation limit (positive watts)
  - Lower bound: effective import / load limit (shown as negative watts)

See replay.py for the client knowledge model and limits.py for limit/ramp resolution.
"""

import logging
from datetime import datetime

from cactus_schema.runner.schema import RequestEntry
from envoy.server.model.subscription import SubscriptionResource
from sqlalchemy.ext.asyncio import AsyncSession

from cactus_orchestrator.power_limit_chart.db import (
    _check_has_storage_target,
    _get_control_groups,
    _get_defaults,
    _get_der_setting,
    _get_does,
    _get_subscribed_group_ids,
)
from cactus_orchestrator.power_limit_chart.limits import (
    _build_receipt_markers,
    _build_trace,
    _collect_event_times,
    _compute_disconnect_intervals,
    _sweep_timeline,
)
from cactus_orchestrator.power_limit_chart.render import _render_html_chart
from cactus_orchestrator.power_limit_chart.replay import (
    _build_group_observations,
    _group_by_gid,
    _replay_control_knowledge,
    _replay_default_knowledge,
)

logger = logging.getLogger(__name__)


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

    Raises ValueError if the client never polled or subscribed to a group's DERControl
    or DefaultDERControl list despite entries existing (a non-compliant client whose
    knowledge cannot be modelled).
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

    has_storage_target = await _check_has_storage_target(session)
    all_does = await _get_does(session, has_storage_target)
    all_defaults = await _get_defaults(session, has_storage_target)

    subscribed_group_ids = await _get_subscribed_group_ids(session)
    default_subscribed_group_ids = await _get_subscribed_group_ids(session, SubscriptionResource.DEFAULT_SITE_CONTROL)

    sorted_requests = sorted(request_history, key=lambda r: r.timestamp)
    derc_observations, dderc_observations = _build_group_observations(
        all_does, all_defaults, sorted_requests, subscribed_group_ids, default_subscribed_group_ids
    )

    segments = _replay_control_knowledge(all_does, derc_observations, groups_by_id, doe_tags or {}, test_start)
    segments_by_group = _group_by_gid(segments)
    defaults_by_group = _replay_default_knowledge(all_defaults, dderc_observations)

    disconnect_intervals = _compute_disconnect_intervals(segments, test_end)

    event_times = _collect_event_times(segments, defaults_by_group, disconnect_intervals, test_start, test_end)

    upper_events, lower_events, step_intervals = _sweep_timeline(
        event_times, sorted_groups, segments_by_group, defaults_by_group, disconnect_intervals, set_max_w, test_end
    )

    video_offset = video_start_seconds or 0.0
    upper_trace = _build_trace(
        upper_events, test_start, test_end, set_max_w, set_max_w, disconnect_intervals, defaults_by_group, video_offset
    )
    lower_trace = _build_trace(
        lower_events, test_start, test_end, -set_max_w, set_max_w, disconnect_intervals, defaults_by_group, video_offset
    )

    receipt_markers = _build_receipt_markers(segments, subscribed_group_ids)

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
