import logging

import pandas as pd
from cactus_runner.models import ReportingData

from cactus_orchestrator.reporting.run_reporting import pdf_report_as_bytes

logger = logging.getLogger(__name__)


async def generate_pdf_report_from_run_artifact(reporting_data: ReportingData) -> bytes | None:

    # Unpack the readings
    readings = {r.reading_type: pd.read_json(r.readings_as_json) for r in reporting_data.readings}
    reading_counts = {r.reading_type: r.reading_counts for r in reporting_data.readings}

    pdf_data = pdf_report_as_bytes(
        runner_state=reporting_data.runner_state,
        check_results=reporting_data.check_results,
        readings=readings,
        reading_counts=reading_counts,
        sites=reporting_data.sites,
        timeline=reporting_data.timeline,
    )

    return pdf_data
