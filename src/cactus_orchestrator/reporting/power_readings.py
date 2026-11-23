"""Measured site/device active power from the runner's timeline, rendered as muted background traces on power charts."""

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

import plotly.graph_objects as go
from cactus_runner.app.timeline import Timeline

# Labels the runner gives its (import positive) measured power streams in cactus_runner.app.timeline.generate_timeline
POWER_STREAM_COLORS = {
    "Site Power": "rgba(60,150,140,0.5)",
    "Device Power": "rgba(175,130,60,0.55)",
}


def add_power_reading_traces(
    fig: go.Figure, timeline: Timeline | None, to_x: Callable[[datetime], Any], export_positive: bool
) -> list[int]:
    """Adds the timeline's measured power streams as muted, non-hoverable traces. Call before adding the main traces so
    these sit beneath. Each value covers its whole interval, so it's drawn as a flat step across it.

    Returns every (signed) watt value plotted"""
    if timeline is None:
        return []

    sign = -1 if export_positive else 1
    interval = timedelta(seconds=timeline.interval_seconds)
    plotted: list[int] = []
    for ds in timeline.data_streams:
        color = POWER_STREAM_COLORS.get(ds.label)
        if color is None:
            continue

        x: list[Any] = []
        y: list[int | None] = []
        for i, watts in enumerate(ds.offset_watt_values):
            start = timeline.start + i * interval
            if watts is None:
                if y and y[-1] is not None:
                    x.append(to_x(start))
                    y.append(None)  # Breaks the line across gaps
                continue
            x.extend([to_x(start), to_x(start + interval)])
            y.extend([sign * watts, sign * watts])
            plotted.append(sign * watts)

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
