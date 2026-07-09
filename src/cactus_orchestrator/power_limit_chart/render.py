"""Plotly rendering of the power limit chart."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import plotly.graph_objects as go  # type: ignore[import-untyped]

from cactus_orchestrator.power_limit_chart.limits import (
    _OP_MOD_CONNECT_GRACE_SECONDS,
    _ReceiptMarker,
)

# Cycling colour palette for step-name bands (semi-transparent fills)
_STEP_PALETTE = [
    "rgba(130,179,255,0.45)",
    "rgba(130,220,170,0.45)",
    "rgba(255,210,120,0.45)",
    "rgba(255,140,170,0.45)",
    "rgba(200,140,255,0.45)",
    "rgba(120,220,220,0.45)",
]


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
    set_max_w: float,
    to_chart_x: Callable[[datetime], datetime],
) -> None:
    for m in receipt_markers:
        color = "#27ae60" if m.is_subscribed else "#e67e22"
        fig.add_shape(
            type="line",
            xref="x",
            yref="paper",
            x0=to_chart_x(m.time),
            x1=to_chart_x(m.time),
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
                x=[to_chart_x(m.time) for m in receipt_markers],
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
    test_end: datetime,
    to_chart_x: Callable[[datetime], datetime],
) -> None:
    _color = "rgba(120,120,120,0.5)"
    reconnect_times = [
        de - timedelta(seconds=_OP_MOD_CONNECT_GRACE_SECONDS)
        for _, de in disconnect_intervals
        if (de - timedelta(seconds=_OP_MOD_CONNECT_GRACE_SECONDS)) < test_end
    ]
    for t in reconnect_times:
        fig.add_shape(
            type="line",
            xref="x",
            yref="paper",
            x0=to_chart_x(t),
            x1=to_chart_x(t),
            y0=0,
            y1=1,
            line=dict(color=_color, width=1, dash="dot"),
        )
    if reconnect_times:
        fig.add_trace(
            go.Scatter(
                x=[to_chart_x(t) for t in reconnect_times],
                y=[0] * len(reconnect_times),
                mode="markers",
                marker=dict(symbol="line-ns", size=10, color=_color),
                customdata=[["60 s AS4777 wGra wait period on reconnection"]] * len(reconnect_times),
                hovertemplate="Device reconnected — %{customdata[0]}<extra>Reconnect</extra>",
                showlegend=False,
            )
        )


def _add_completion_markers(
    fig: go.Figure,
    completions: list[tuple[str, datetime]],
    lanes: list[int],
    lane_y: list[float],
    test_start: datetime,
    test_end: datetime,
    to_chart_x: Callable[[datetime], datetime],
) -> None:
    _completion_color = "#888"
    for (name, t), lane in zip(completions, lanes, strict=False):
        if t < test_start or t > test_end:
            continue
        fig.add_shape(
            type="line",
            xref="x",
            yref="paper",
            x0=to_chart_x(t),
            x1=to_chart_x(t),
            y0=0,
            y1=1,
            line=dict(color=_completion_color, width=1.5, dash="dash"),
            opacity=0.45,
        )
        label = name if len(name) <= 22 else name[:20] + "…"
        fig.add_annotation(
            xref="x",
            yref="paper",
            x=to_chart_x(t),
            y=lane_y[lane],
            text=label,
            showarrow=True,
            arrowhead=0,
            arrowcolor=_completion_color,
            arrowwidth=1,
            ax=0,
            ay=12,
            font=dict(size=8, color=_completion_color),
            xanchor="center",
            yanchor="bottom",
        )
    fig.add_trace(
        go.Scatter(
            x=[None],
            y=[None],
            mode="lines",
            line=dict(color=_completion_color, width=1.5, dash="dash"),
            name="Step complete",
        )
    )


def _add_step_strips(
    fig: go.Figure,
    step_intervals: list[tuple[str, datetime, datetime]],
    test_start: datetime,
    test_end: datetime,
    to_chart_x: Callable[[datetime], datetime],
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
        x0 = max(start, test_start)
        x1 = min(end, test_end)
        if x1 <= x0:
            continue
        fig.add_shape(
            type="rect",
            xref="x",
            yref="paper",
            x0=to_chart_x(x0),
            x1=to_chart_x(x1),
            y0=-0.42,
            y1=-0.22,
            fillcolor=color,
            line=dict(color="rgba(0,0,0,0.18)", width=0.5),
            layer="below",
        )
        if (x1 - x0).total_seconds() >= 20:
            label = name if len(name) <= 20 else name[:18] + "…"
            fig.add_annotation(
                xref="x",
                yref="paper",
                x=to_chart_x(x0) + (x1 - x0) / 2,
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

    # Rebase datetimes to a fake epoch so Plotly's auto-ticking shows relative/video
    # time instead of UTC. test_start maps to 1970-01-01T00:00:00Z + video_offset.
    _fake_epoch = datetime(1970, 1, 1, tzinfo=UTC)
    _video_offset = timedelta(seconds=video_start_seconds or 0.0)

    def to_chart_x(t: datetime) -> datetime:
        return _fake_epoch + _video_offset + (t - test_start)

    y_max = set_max_w * 1.1
    y_min = -set_max_w * 1.1
    has_steps = bool(step_intervals)
    bottom_margin = 230 if has_steps else 130
    completions = sorted(step_completions or [], key=lambda x: x[1])
    lanes = (
        _assign_completion_lanes(completions, lambda t: (t - test_start).total_seconds(), duration_secs)
        if completions
        else []
    )
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
            x=[to_chart_x(t) for t, _, _ in upper_trace],
            y=[v for _, v, _ in upper_trace],
            mode="lines",
            name="Upper limit (Export / Gen)",
            line=dict(color="#e74c3c", width=2),
            customdata=[[h] for _, _, h in upper_trace],
            hovertemplate="%{customdata[0]}<extra>Upper</extra>",
        )
    )
    fig.add_trace(
        go.Scatter(
            x=[to_chart_x(t) for t, _, _ in lower_trace],
            y=[v for _, v, _ in lower_trace],
            mode="lines",
            name="Lower limit (Import / Load)",
            line=dict(color="#3498db", width=2),
            customdata=[[h] for _, _, h in lower_trace],
            hovertemplate="%{customdata[0]}<extra>Lower</extra>",
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
    _add_receipt_markers(fig, receipt_markers, set_max_w, to_chart_x)
    _add_reconnect_markers(fig, disconnect_intervals, test_end, to_chart_x)
    if completions:
        _add_completion_markers(fig, completions, lanes, lane_y, test_start, test_end, to_chart_x)
    if has_steps:
        _add_step_strips(fig, step_intervals, test_start, test_end, to_chart_x)

    x_title = "Video time" if video_start_seconds else "Time from test start"
    chart_start = to_chart_x(test_start)
    chart_end = to_chart_x(test_end)

    # ── Layout ───────────────────────────────────────────────────────────────
    fig.update_layout(
        title=dict(text="Expected Device Power Limits", font=dict(size=16)),
        height=height,
        xaxis=dict(
            title=x_title,
            type="date",
            range=[chart_start, chart_end],
            tickformatstops=[
                dict(dtickrange=[None, 60000], value="%M:%S"),
                dict(dtickrange=[60000, None], value="%H:%M"),
            ],
            hoverformat="%H:%M:%S",
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
