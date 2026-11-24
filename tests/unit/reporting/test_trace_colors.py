from cactus_orchestrator.reporting.trace_colors import (
    CONTROL_COLORS,
    FALLBACK_COLORS,
    OTHER_COLOR,
    POWER_STREAM_COLORS,
    timeline_stream_colors,
)


def test_timeline_stream_colors():
    labels = [
        "Site Power",
        "Device Power",
        "/derp/1 opModExpLimW",
        "/derp/1 opModImpLimW",
        "/derp/2 opModExpLimW",
        "/derp/3 opModGenLimW",
        "/derp/4 opModLoadLimW",
        "Default opModExpLimW",
        "Default opModStorageTargetW",
        "Something new",
        "Something else new",
    ]

    colors = timeline_stream_colors(labels)

    assert colors == {
        "Site Power": POWER_STREAM_COLORS["Site Power"],
        "Device Power": POWER_STREAM_COLORS["Device Power"],
        # First program gets the base colour, each later program a lighter shade (capped)
        "/derp/1 opModExpLimW": CONTROL_COLORS["opModExpLimW"],
        "/derp/1 opModImpLimW": CONTROL_COLORS["opModImpLimW"],
        "/derp/2 opModExpLimW": "#ef8b80",  # 35% towards white
        "/derp/3 opModGenLimW": "#e1c0bc",  # 70% towards white
        "/derp/4 opModLoadLimW": "#becbe1",  # capped at 70%
        # Defaults match their control's base colour
        "Default opModExpLimW": CONTROL_COLORS["opModExpLimW"],
        "Default opModStorageTargetW": CONTROL_COLORS["opModStorageTargetW"],
        # Unrecognised streams use the fallbacks, then grey
        "Something new": FALLBACK_COLORS[0],
        "Something else new": OTHER_COLOR,
    }
