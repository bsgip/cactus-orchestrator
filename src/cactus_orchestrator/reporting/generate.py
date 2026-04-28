import io
import logging

import pandas as pd
from cactus_runner.models import ReportingData_v1

from cactus_orchestrator.reporting.run_reporting import pdf_report_as_bytes

logger = logging.getLogger(__name__)


async def generate_pdf_report_v1(reporting_data: ReportingData_v1) -> bytes | None:

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
        set_max_w_varied=reporting_data.set_max_w_varied,
    )

    return pdf_data
