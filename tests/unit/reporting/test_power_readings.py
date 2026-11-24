from datetime import UTC, datetime

import plotly.graph_objects as go
import pytest
from cactus_runner.app.timeline import Timeline, TimelineDataStream

from cactus_orchestrator.reporting.power_readings import add_power_reading_traces, is_import_positive_power_release

T0 = datetime(2026, 12, 1, 12, 0, 0, tzinfo=UTC)


def _to_seconds(t: datetime) -> float:
    return (t - T0).total_seconds()


def test_add_power_reading_traces_none_timeline():
    fig = go.Figure()
    assert add_power_reading_traces(fig, None, _to_seconds, export_positive=True) == []
    assert len(fig.data) == 0


@pytest.mark.parametrize("export_positive, sign", [(False, 1), (True, -1)])
def test_add_power_reading_traces(export_positive, sign):
    timeline = Timeline(
        T0,
        20,
        [
            TimelineDataStream("/derp/1 opModExpLimW", [-500, -500, -500, -500], True, False),
            TimelineDataStream("Site Power", [100, 200, None, 300], False, False),
            TimelineDataStream("Device Power", [None, -50, -50, None], False, False),
        ],
    )
    fig = go.Figure()

    plotted = add_power_reading_traces(fig, timeline, _to_seconds, export_positive=export_positive)

    # Only the power streams are added - each value is a step across its interval, with gaps breaking the line. A
    # leading gap doesn't add a break.
    assert [t.name for t in fig.data] == ["Site Power (measured)", "Device Power (measured)"]
    site, device = fig.data
    assert list(site.x) == [0, 20, 20, 40, 40, 60, 80]
    assert list(site.y) == [sign * 100, sign * 100, sign * 200, sign * 200, None, sign * 300, sign * 300]
    assert list(device.x) == [20, 40, 40, 60, 60]
    assert list(device.y) == [sign * -50, sign * -50, sign * -50, sign * -50, None]
    assert all(t.hoverinfo == "skip" for t in fig.data)
    assert all(t.legendrank == 1001 for t in fig.data)
    assert plotted == [sign * v for v in [100, 200, 300, -50, -50]]


@pytest.mark.parametrize(
    "deploy_release_tag, expected",
    [(None, False), ("podman21", False), ("197", False), ("198", True), ("1000", True)],
)
def test_is_import_positive_power_release(deploy_release_tag, expected):
    assert is_import_positive_power_release(deploy_release_tag) is expected
