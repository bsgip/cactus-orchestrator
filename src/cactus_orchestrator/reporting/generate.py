import io
import logging

import pandas as pd
from cactus_runner.models import ReportingData, ReportingData_v1

from cactus_orchestrator.reporting.error import PdfGenerationError
from cactus_orchestrator.reporting.run_reporting import pdf_report_as_bytes

logger = logging.getLogger(__name__)


async def generate_pdf_report_v1(
    reporting_data: ReportingData_v1, playlist_info: str | None = None, deploy_release_tag: str | None = None
) -> bytes:

    # Unpack the readings: time_period_start is serialised as epoch ms integers by to_json(), so we explicitly convert
    # it back to datetime; pd.read_json convert_dates heuristic doesn't match the column name and would leave it int64.
    readings = {}
    for r in reporting_data.readings:
        if r.readings_as_json is not None:
            df = pd.read_json(io.StringIO(r.readings_as_json))
            df["time_period_start"] = pd.to_datetime(df["time_period_start"], unit="ms", utc=True)
            readings[r.reading_type] = df
    reading_counts = {r.reading_type: r.reading_counts for r in reporting_data.readings}

    pdf_data = pdf_report_as_bytes(
        runner_state=reporting_data.runner_state,
        check_results=reporting_data.check_results,
        readings=readings,
        reading_counts=reading_counts,
        sites=reporting_data.sites,
        timeline=reporting_data.timeline,
        warnings=reporting_data.warnings,
        playlist_info=playlist_info,
        deploy_release_tag=deploy_release_tag,
    )

    return pdf_data


def parse_reporting_data(raw_reporting_data_version: int, raw_reporting_data: str) -> ReportingData_v1 | None:
    """Parses the finalisation/reporting data from runner into a versioned instance - or None if it cannot be parsed"""
    try:
        return ReportingData.from_json(raw_reporting_data_version, raw_reporting_data)
    except Exception as exc:
        msg = "Failed to convert json to ReportingData instance."
        logger.error(msg, exc_info=exc)
        return None


async def generate_pdf_report(
    raw_reporting_data: str,
    raw_reporting_data_version: int,
    playlist_info: str | None = None,
    deploy_release_tag: str | None = None,
) -> bytes:
    """A pdf run report is generated from `reporting_data` which then returned as a stream of PDF data (raw bytes).

    Offloads to the correct "generation algorithm" depending on how old the supplied reporting data is.

    On failure raises PdfGenerationError

    Args:
        raw_reporting_data (str): ReportingData as a json encoded string
        playlist_info (str | None): "Test N of M" label for playlist runs.
        deploy_release_tag (str | None): the cactus-deploy release tag that was live for this run's pod
            (Run.deploy_release_tag).
    Returns:
        bytes: the updated zip file data.
    """

    reporting_data = parse_reporting_data(raw_reporting_data_version, raw_reporting_data)
    if reporting_data is None:
        raise PdfGenerationError(f"Cannot create v{raw_reporting_data_version} reporting data from JSON")

    try:
        reporting_data = ReportingData.from_json(raw_reporting_data_version, raw_reporting_data)
    except Exception as exc:
        msg = "Failed to convert json to ReportingData instance."
        logger.error(msg, exc_info=exc)
        raise PdfGenerationError(f"Artifact regeneration error: {msg}") from exc

    try:
        if raw_reporting_data_version == 1:
            return await generate_pdf_report_v1(
                reporting_data=reporting_data, deploy_release_tag=deploy_release_tag, playlist_info=playlist_info
            )
        else:
            raise ValueError(f"Unknown version of reporting data ({raw_reporting_data_version})")
    except Exception as exc:
        msg = "Failed to generate pdf report from reporting data."
        logger.error(msg, exc_info=exc)
        raise PdfGenerationError(f"PDF generation error {msg}") from exc
