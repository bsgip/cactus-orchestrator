"""Measured site/device active power from the runner's timeline, rendered as muted background traces on power charts."""

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

import plotly.graph_objects as go
from cactus_runner.app.timeline import Timeline

from cactus_orchestrator.reporting.trace_colors import POWER_STREAM_COLORS


def interval_step_xy(
    timeline: Timeline, values: list[int | None], to_x: Callable[[datetime], Any]
) -> tuple[list[Any], list[int | None]]:
    """Line points drawing each timeline value as a flat step across its whole interval, with gaps breaking the line"""
    interval = timedelta(seconds=timeline.interval_seconds)
    x: list[Any] = []
    y: list[int | None] = []
    for i, watts in enumerate(values):
        start = timeline.start + i * interval
        if watts is None:
            if y and y[-1] is not None:
                x.append(to_x(start))
                y.append(None)
            continue
        x.extend([to_x(start), to_x(start + interval)])
        y.extend([watts, watts])
    return x, y


def add_power_reading_traces(
    fig: go.Figure, timeline: Timeline | None, to_x: Callable[[datetime], Any], export_positive: bool
) -> list[int]:
    """Adds the timeline's measured power streams as muted, non-hoverable traces. Call before adding the main traces so
    these sit beneath. Each value covers its whole interval, so it's drawn as a flat step across it.

    Returns every (signed) watt value plotted"""
    if timeline is None:
        return []

    sign = -1 if export_positive else 1
    plotted: list[int] = []
    for ds in timeline.data_streams:
        color = POWER_STREAM_COLORS.get(ds.label)
        if color is None:
            continue

        values = [None if w is None else sign * w for w in ds.offset_watt_values]
        plotted.extend(w for w in values if w is not None)
        x, y = interval_step_xy(timeline, values, to_x)

        fig.add_trace(
            go.Scatter(
                x=x,
                y=y,
                mode="lines",
                name=f"{ds.label} (measured)",
                line=dict(color=color, width=1.5),
                hoverinfo="skip",
                legendrank=1001,  # Listed after the main traces (default rank 1000) despite being added first
            )
        )

    return plotted
