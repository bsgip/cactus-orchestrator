"""Fixed colours for the runner's timeline data streams, shared by the PDF timeline chart and the HTML power limit chart
so each limit / reading looks the same everywhere."""

EXPORT_LIMIT_COLOR = "#e74c3c"
IMPORT_LIMIT_COLOR = "#3498db"

# Keyed on the opMod suffix of the runner's control labels, eg "/derp/{id} opModExpLimW" or "Default opModExpLimW"
CONTROL_COLORS = {
    "opModExpLimW": EXPORT_LIMIT_COLOR,
    "opModGenLimW": "#9b2d20",
    "opModImpLimW": IMPORT_LIMIT_COLOR,
    "opModLoadLimW": "#28539c",
    "opModStorageTargetW": "#1e9e5a",
}

# Labels the runner gives its measured power streams in cactus_runner.app.timeline.generate_timeline.
POWER_STREAM_COLORS = {"Site Power": "rgba(90,110,150,0.5)", "Device Power": "rgba(175,130,60,0.55)"}

# Unrecognised streams get the only extra hue that stays distinct from the above, then fall back to grey
FALLBACK_COLORS = ["#e0a800"]
OTHER_COLOR = "#7f7f7f"

PROGRAM_LIGHTEN_STEP = 0.35  # Each additional DERProgram's controls are this much lighter (blended towards white)
MAX_PROGRAM_LIGHTEN = 0.7


def _lighten(hex_color: str, amount: float) -> str:
    rgb = (int(hex_color[i : i + 2], 16) for i in (1, 3, 5))
    return "#" + "".join(f"{round(c + (255 - c) * amount):02x}" for c in rgb)


def timeline_stream_colors(labels: list[str]) -> dict[str, str]:
    """Colour for each timeline data stream label. Controls are coloured by their opMod, with each additional
    DERProgram (in order of appearance) a lighter shade. Defaults match their control (the runner dashes them)."""
    programs = list(dict.fromkeys(label.split(" ")[0] for label in labels if label.startswith("/derp/")))
    fallbacks = iter(FALLBACK_COLORS)

    colors: dict[str, str] = {}
    for label in labels:
        if label in POWER_STREAM_COLORS:
            colors[label] = POWER_STREAM_COLORS[label]
            continue

        prefix, _, opmod = label.rpartition(" ")
        base = CONTROL_COLORS.get(opmod)
        if base is None:
            colors[label] = next(fallbacks, OTHER_COLOR)
        elif prefix in programs:
            colors[label] = _lighten(base, min(programs.index(prefix) * PROGRAM_LIGHTEN_STEP, MAX_PROGRAM_LIGHTEN))
        else:
            colors[label] = base
    return colors
