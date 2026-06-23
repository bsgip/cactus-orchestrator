from datetime import UTC, datetime

import pytest
from assertical.fixtures.postgres import generate_async_session
from sqlalchemy import select
from sqlalchemy.orm import joinedload, selectinload

from cactus_orchestrator.artifact import determine_compliance
from cactus_orchestrator.model import ComplianceRequest, User
from cactus_orchestrator.reporting.compliance_reporting import pdf_report_as_bytes


@pytest.mark.asyncio
async def test_pdf_report_as_bytes(pg_compliance_config):
    # Arrange
    compliance_request_id = 1
    requester_id = 3  # admin user
    async with generate_async_session(pg_compliance_config) as session:
        requester = (await session.execute(select(User).where(User.user_id == requester_id))).scalar_one()
        stmt = select(ComplianceRequest).where(ComplianceRequest.compliance_request_id == compliance_request_id)
        stmt = stmt.options(selectinload(ComplianceRequest.classes))
        stmt = stmt.options(selectinload(ComplianceRequest.runs))
        stmt = stmt.options(joinedload(ComplianceRequest.created_by_user))
        compliance_request = (await session.execute(stmt)).scalar_one()
        compliance_classes, excluded_classes, class_to_test_procedures, compliance_runs = determine_compliance(
            compliance_request=compliance_request
        )

    # Act
    report = pdf_report_as_bytes(
        requester=requester,
        user=compliance_request.created_by_user,
        name="",
        name_id=f"{compliance_request.compliance_request_id}",
        name_type="Compliance Request",
        csip_aus_version=compliance_request.csip_aus_version,
        finalisation_datetime=datetime.now(UTC),
        compliance_id=compliance_request.compliance_request_id,
        compliance_classes=compliance_classes,
        excluded_compliance_classes=excluded_classes,
        class_to_test_procedures=class_to_test_procedures,
        compliance_runs=compliance_runs,
    )

    # Assert
    assert len(report) > 0

    # Optional: Save and open the PDF
    # import os
    # import subprocess
    # import tempfile
    # import uuid
    #
    # with tempfile.NamedTemporaryFile(suffix=".pdf", prefix=f"report_{uuid.uuid4().hex[:8]}_", delete=False) as f:
    #     f.write(report)
    #     f.flush()
    #     print(f"Saved comprehensive PDF report: {os.path.basename(f.name)}")
    #     subprocess.run(["xdg-open", f.name])
