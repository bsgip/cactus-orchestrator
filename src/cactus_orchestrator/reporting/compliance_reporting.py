import io
import logging
from dataclasses import dataclass
from functools import partial

import PIL.Image as PilImage
import plotly.graph_objects as go  # type: ignore
from cactus_runner import __version__ as cactus_runner_version
from cactus_test_definitions import __version__ as cactus_test_definitions_version
from reportlab.lib.colors import Color, HexColor
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    BaseDocTemplate,
    Flowable,
    Image,
    NullDraw,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from cactus_orchestrator import __version__ as cactus_orchestrator_version
from cactus_orchestrator.model import ComplianceRecord, RunGroup, User

logger = logging.getLogger(__name__)


CHART_MARGINS = dict(l=80, r=20, t=40, b=80)


class ConditionalSpacer(Spacer):
    """A Spacer that takes up a variable amount of vertical space.

    It takes up the avilable space, up to but not exceeding
    the requested height of the spacer.
    """

    def wrap(self, aW: float, aH: float) -> tuple[float, float]:
        height = min(self.height, aH - 1e-8)
        return (aW, height)


PAGE_WIDTH, PAGE_HEIGHT = A4
DEFAULT_SPACER = ConditionalSpacer(1, 0.25 * inch)
MARGIN = 0.5 * inch
BANNER_HEIGHT = inch

HIGHLIGHT_COLOR = HexColor(0x09BB71)  # Teal green used on cactus UI
MUTED_COLOR = HexColor(0xD7FCEF)  # Light mint green
WHITE = HexColor(0xFFFFFF)

TABLE_TEXT_COLOR = HexColor(0x262626)
TABLE_FONT_SIZE = 10
TABLE_FONT_NAME = "Helvetica-Bold"
TABLE_HEADER_TEXT_COLOR = HexColor(0x424242)
TABLE_ROW_COLOR = WHITE
TABLE_ALT_ROW_COLOR = MUTED_COLOR
TABLE_LINE_COLOR = HexColor(0x707070)

OVERVIEW_BACKGROUND = MUTED_COLOR

WARNING_COLOR = HexColor(0xFF4545)
TEXT_COLOR = HexColor(0x000000)
PASS_COLOR = HIGHLIGHT_COLOR
FAIL_COLOR = HexColor(0xF1420E)
GENTLE_WARNING_COLOR = HexColor(0xFFC107)

DEFAULT_TABLE_STYLE = TableStyle(
    [
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [TABLE_ROW_COLOR, TABLE_ALT_ROW_COLOR]),
        ("TEXTCOLOR", (0, 0), (-1, -1), TABLE_TEXT_COLOR),
        ("TEXTCOLOR", (0, 0), (-1, 0), TABLE_HEADER_TEXT_COLOR),
        ("FONTNAME", (0, 0), (-1, 0), TABLE_FONT_NAME),
        ("FONTSIZE", (0, 0), (-1, 0), TABLE_FONT_SIZE),
        ("LINEBELOW", (0, 0), (-1, 0), 1, TABLE_LINE_COLOR),
        ("LINEBELOW", (0, -1), (-1, -1), 1, TABLE_LINE_COLOR),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
)

# Limit document content to full width of page (minus margins)
MAX_CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGIN

# The maximum length of a string that can appear in a single table cell
MAX_CELL_LENGTH_CHARS = 500

DOCUMENT_TITLE = "CSIP-AUS Client Compliance"
AUTHOR = "Cactus Test Harness"
AUTHOR_URL = "https://cactus.cecs.anu.edu.au"

# Pad compliance ids with leading zeroes to a length of...
COMPLIANCE_ID_LENGTH = 6


def rl_to_plotly_color(reportlab_color: Color) -> str:
    """Converts a reportlab color to plotly color (as hexstring)"""
    return f"#{reportlab_color.hexval()[2:]}"


@dataclass
class StyleSheet:
    """A collection of all the styles used in the PDF report"""

    title: ParagraphStyle
    heading: ParagraphStyle
    subheading: ParagraphStyle
    normal: ParagraphStyle
    overview_table: ParagraphStyle
    table: TableStyle
    table_width: float
    spacer: Spacer | NullDraw
    date_format: str
    max_cell_length_chars: int
    truncation_marker: str


def get_stylesheet() -> StyleSheet:
    sample_style_sheet = getSampleStyleSheet()
    return StyleSheet(
        title=ParagraphStyle(
            name="Title",
            parent=sample_style_sheet["Normal"],
            fontName=sample_style_sheet["Title"].fontName,
            fontSize=28,
            leading=22,
            spaceAfter=3,
        ),
        heading=sample_style_sheet.get("Heading2"),  # type: ignore
        subheading=sample_style_sheet.get("Heading3"),  # type: ignore
        normal=sample_style_sheet.get("Normal"),  # type: ignore
        overview_table=ParagraphStyle(
            name="OverviewTable", parent=sample_style_sheet["Normal"], fontSize=8, fontName="Helvetica"
        ),  # type: ignore
        table=DEFAULT_TABLE_STYLE,
        table_width=MAX_CONTENT_WIDTH,
        spacer=DEFAULT_SPACER,
        date_format="%Y-%m-%d %H:%M:%S",
        max_cell_length_chars=MAX_CELL_LENGTH_CHARS,
        truncation_marker=" … ",
    )


def first_page_template(canvas: Canvas, doc: BaseDocTemplate, compliance_id: str, csip_aus_version: str) -> None:
    """Template for the first/front/title page of the report"""

    canvas.saveState()

    # Banner
    canvas.setFillColor(HIGHLIGHT_COLOR)
    canvas.rect(0, PAGE_HEIGHT - BANNER_HEIGHT, PAGE_WIDTH, BANNER_HEIGHT, stroke=0, fill=1)

    # Title (Banner)
    canvas.setFillColor(TEXT_COLOR)
    canvas.setFont("Helvetica-Bold", 16)
    canvas.drawString(MARGIN, PAGE_HEIGHT - 0.6 * inch, DOCUMENT_TITLE)

    # Report author details
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 10)
    canvas.drawRightString(PAGE_WIDTH - MARGIN, PAGE_HEIGHT - 0.5 * inch, AUTHOR)
    # canvas.linkURL("https://cactus.cecs.anu.edu.au")
    canvas.drawRightString(PAGE_WIDTH - MARGIN, PAGE_HEIGHT - 0.7 * inch, AUTHOR_URL)

    # Footer
    # Footer Banner
    canvas.setFillColor(HIGHLIGHT_COLOR)
    canvas.rect(0, 0, PAGE_WIDTH, 0.4 * inch, stroke=0, fill=1)
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 8)
    footer_offset = 0.2 * inch
    # Footer left
    canvas.drawString(MARGIN, footer_offset, f"Compliance No. #{compliance_id}")
    # Footer mid
    canvas.drawCentredString(PAGE_WIDTH / 2.0, footer_offset, f"CSIP-Aus {csip_aus_version} Compliance Report")
    # Footer right
    canvas.drawRightString(PAGE_WIDTH - MARGIN, footer_offset, f"Page {doc.page}")
    canvas.restoreState()

    # Document "Metadata"
    canvas.setFillColor(TEXT_COLOR)
    canvas.setFont("Helvetica", 6)
    canvas.drawRightString(
        PAGE_WIDTH - MARGIN,
        PAGE_HEIGHT - BANNER_HEIGHT - 0.2 * inch,
        f"Cactus Orchestrator v{cactus_orchestrator_version}",
    )
    canvas.drawRightString(
        PAGE_WIDTH - MARGIN,
        PAGE_HEIGHT - BANNER_HEIGHT - 0.35 * inch,
        f"Cactus Test Definitions v{cactus_test_definitions_version}",
    )
    canvas.drawRightString(
        PAGE_WIDTH - MARGIN, PAGE_HEIGHT - BANNER_HEIGHT - 0.5 * inch, f"Cactus Runner v{cactus_runner_version}"
    )
    # canvas.drawRightString(
    #     PAGE_WIDTH - MARGIN, PAGE_HEIGHT - BANNER_HEIGHT - 0.65 * inch, f"CSIP Aus {csip_aus_version}"
    # )


def later_pages_template(canvas: Canvas, doc: BaseDocTemplate, compliance_id: str, csip_aus_version: str) -> None:
    """Template for subsequent pages"""
    canvas.saveState()
    # Footer
    # Footer Banner
    canvas.setFillColor(HIGHLIGHT_COLOR)
    canvas.rect(0, 0, PAGE_WIDTH, 0.4 * inch, stroke=0, fill=1)
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica", 8)
    footer_offset = 0.2 * inch
    # Footer left
    canvas.drawString(MARGIN, footer_offset, f"Compliance No. #{compliance_id}")
    # Footer mid
    canvas.drawCentredString(PAGE_WIDTH / 2.0, footer_offset, f"CSIP-Aus {csip_aus_version} Compliance Report")
    # Footer right
    canvas.drawRightString(PAGE_WIDTH - MARGIN, footer_offset, f"Page {doc.page}")
    canvas.restoreState()


def fig_to_image(fig: go.Figure, content_width: float) -> Image:
    UPSCALE_FACTOR = 4
    img_bytes = fig.to_image(format="png", scale=UPSCALE_FACTOR)  # Scale up figure so it's high enough resolution
    pil_image = PilImage.open(io.BytesIO(img_bytes))
    buffer = io.BytesIO(img_bytes)
    scale_factor = pil_image.width / content_width  # rescale image to width of page content
    return Image(buffer, width=pil_image.width / scale_factor, height=pil_image.height / scale_factor)


def generate_overview_section(
    requester: User,
    user: User,
    run_group: RunGroup,
    compliance_record: ComplianceRecord,
    stylesheet: StyleSheet,
) -> list[Flowable]:

    csip_aus_version = f"CSIP-Aus {run_group.csip_aus_version}"

    elements: list[Flowable] = []
    elements.append(Paragraph("Compliance Report", style=stylesheet.title))
    elements.append(Paragraph(csip_aus_version, style=stylesheet.subheading))
    elements.append(stylesheet.spacer)

    overview_data = [
        [
            "User",
            Paragraph(f"{user.user_name} <i>(ID {user.user_id})</i>", style=stylesheet.overview_table),
            "",
            "Generated on",
            f"{compliance_record.created_at}",
        ],
        [
            "Run group",
            Paragraph(f"{run_group.name} <i>(ID {run_group.run_group_id})</i>", style=stylesheet.overview_table),
            "",
            "by",
            Paragraph(f"{requester.user_name} <i>(ID {requester.user_id})</i>", style=stylesheet.overview_table),
        ],
    ]

    column_widths = [int(fraction * stylesheet.table_width) for fraction in [0.15, 0.30, 0.10, 0.15, 0.30]]
    table = Table(overview_data, colWidths=column_widths)
    tstyle = TableStyle(
        [
            ("BACKGROUND", (0, 0), (1, 2), OVERVIEW_BACKGROUND),
            ("BACKGROUND", (3, 0), (4, 2), OVERVIEW_BACKGROUND),
            ("TEXTCOLOR", (0, 0), (-1, -1), TABLE_TEXT_COLOR),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("FONTNAME", (0, 0), (0, 2), "Helvetica-Bold"),
            ("FONTNAME", (3, 0), (3, 2), "Helvetica-Bold"),
            ("TOPPADDING", (0, 0), (4, 0), 6),
            ("BOTTOMPADDING", (0, 2), (4, 2), 6),
        ]
    )
    table.setStyle(tstyle)
    elements.append(table)
    elements.append(stylesheet.spacer)
    return elements


def to_comma_separated_list(items: list[str]) -> str:
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return f"{', '.join(items[:-1])} and {items[-1]}"


def generate_compliance_table(
    compliance_by_class: dict,
    stylesheet: StyleSheet,
) -> Table:
    # Generate table data
    compliance_data = []
    for c in compliance_by_class.values():
        if c.is_compliant:
            runs = [rc.run.test_procedure_id for rc in c.per_run_compliance]
            compliance_data.append([c.class_details.name, to_comma_separated_list(runs)])

    # Add table header
    compliance_data.insert(0, ["Class", "Test Procedures"])

    # Create the table
    column_widths = [int(fraction * stylesheet.table_width) for fraction in [0.15, 0.85]]
    table = Table(compliance_data, colWidths=column_widths)
    table.setStyle(stylesheet.table)

    return table


def generate_compliance_summary(
    run_group: RunGroup,
    compliance_record: ComplianceRecord,
    compliance_by_class: dict,
    stylesheet: StyleSheet,
) -> list[Flowable]:
    elements: list[Flowable] = []
    elements.append(Paragraph("Compliance Summary", stylesheet.heading))
    elements.append(
        Paragraph(
            (
                "The following compliance classes defined under"
                f" <b>CSIP-Aus {run_group.csip_aus_version}</b> have been attained by"
                f" <b>{run_group.name}</b> on <i>{compliance_record.created_at}</i>."
            )
        )
    )
    elements.append(stylesheet.spacer)
    table = generate_compliance_table(compliance_by_class=compliance_by_class, stylesheet=stylesheet)

    elements.append(table)
    elements.append(stylesheet.spacer)

    elements.append(Paragraph("The following compliance classes have <b>not</b> been met."))

    excluded_classes = []
    for c in compliance_by_class.values():
        if not c.is_compliant:
            excluded_classes.append(f"<b>{c.class_details.name}</b>")
    elements.append(Paragraph(to_comma_separated_list(sorted(excluded_classes))))
    elements.append(stylesheet.spacer)

    return elements


def generate_runs_table(compliance_by_class: dict, stylesheet: StyleSheet) -> Table:
    # Generate table data
    procedures = {}
    for c in compliance_by_class.values():
        if c.is_compliant:
            for rc in c.per_run_compliance:
                id = rc.run.test_procedure_id
                if id not in procedures:
                    procedures[id] = rc.run

    runs_data = []
    for k in sorted(procedures.keys()):
        runs_data.append([k, procedures[k].latest_run_id, procedures[k].latest_run_timestamp])

    # Add table header
    runs_data.insert(0, ["Test Procedure", "Run ID", "Timestamp"])

    # Create the table
    column_widths = [int(fraction * stylesheet.table_width) for fraction in [0.45, 0.15, 0.4]]
    table = Table(runs_data, colWidths=column_widths)
    table.setStyle(stylesheet.table)

    return table


def generate_runs_section(
    compliance_by_class: dict,
    stylesheet: StyleSheet,
) -> list[Flowable]:
    elements: list[Flowable] = []
    elements.append(Paragraph("Contributing Runs", stylesheet.heading))
    elements.append(stylesheet.spacer)
    table = generate_runs_table(compliance_by_class=compliance_by_class, stylesheet=stylesheet)
    elements.append(table)
    elements.append(stylesheet.spacer)

    return elements


def generate_page_elements(
    requester: User,
    user: User,
    run_group: RunGroup,
    compliance_by_class: dict,
    compliance_record: ComplianceRecord,
    stylesheet: StyleSheet,
) -> list[Flowable]:
    # raise ValueError("'active_test_procedure' attribute of 'runner_state' cannot be None")

    page_elements: list[Flowable] = []

    # The title is handles by the first page banner
    # We need a space to skip past the banner
    page_elements.append(Spacer(1, MARGIN))

    # Overview Section
    try:
        page_elements.extend(
            generate_overview_section(
                compliance_record=compliance_record,
                run_group=run_group,
                requester=requester,
                user=user,
                stylesheet=stylesheet,
            )
        )
    except ValueError as e:
        # ValueError is raised by 'first_client_interaction_of_type' if it can find the required
        # client interations. This is a guard-rail. If we have an active test procedure then
        # the appropriate client interactions SHOULD be defined in the runner state.
        logger.error(f"Unable to add compliance overview to PDF report. Reason={repr(e)}")

    # Compliance Summary Section
    try:
        page_elements.extend(
            generate_compliance_summary(
                compliance_record=compliance_record,
                run_group=run_group,
                compliance_by_class=compliance_by_class,
                stylesheet=stylesheet,
            )
        )
    except ValueError as e:
        # ValueError is raised by 'first_client_interaction_of_type' if it can find the required
        # client interations. This is a guard-rail. If we have an active test procedure then
        # the appropriate client interactions SHOULD be defined in the runner state.
        logger.error(f"Unable to add compliance summary to PDF report. Reason={repr(e)}")

    # Contributing Runs Section
    try:
        page_elements.extend(generate_runs_section(compliance_by_class=compliance_by_class, stylesheet=stylesheet))
    except ValueError as e:
        # ValueError is raised by 'first_client_interaction_of_type' if it can find the required
        # client interations. This is a guard-rail. If we have an active test procedure then
        # the appropriate client interactions SHOULD be defined in the runner state.
        logger.error(f"Unable to add runs section to PDF report. Reason={repr(e)}")

    return page_elements


def pdf_report_as_bytes(
    requester: User,
    user: User,
    run_group: RunGroup,
    compliance_by_class: dict,
    compliance_record: ComplianceRecord,
    no_spacers: bool = False,
) -> bytes:
    stylesheet = get_stylesheet()
    if no_spacers:
        stylesheet.spacer = NullDraw()

    # raise ValueError("Unable to compliance generate report - no data supplied")

    page_elements = generate_page_elements(
        requester=requester,
        user=user,
        run_group=run_group,
        compliance_by_class=compliance_by_class,
        compliance_record=compliance_record,
        stylesheet=stylesheet,
    )

    csip_aus_version = run_group.csip_aus_version
    compliance_id = str(compliance_record.compliance_record_id).zfill(COMPLIANCE_ID_LENGTH)

    first_page = partial(
        first_page_template,
        compliance_id=compliance_id,
        csip_aus_version=csip_aus_version,
    )
    later_pages = partial(later_pages_template, compliance_id=compliance_id, csip_aus_version=csip_aus_version)

    with io.BytesIO() as buffer:
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            title=DOCUMENT_TITLE,
            author=AUTHOR,
            leftMargin=MARGIN,
            rightMargin=MARGIN,
            topMargin=MARGIN,
            bottomMargin=MARGIN,
        )
        doc.build(page_elements, onFirstPage=first_page, onLaterPages=later_pages)
        pdf_data = buffer.getvalue()

    return pdf_data
