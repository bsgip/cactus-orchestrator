import pytest
from assertical.fixtures.postgres import generate_async_session
from sqlalchemy import select

from cactus_orchestrator.model import ComplianceRecord, RunGroup, User
from cactus_orchestrator.reporting.compliance import get_compliance_for_run_group, get_procedure_mapping
from cactus_orchestrator.reporting.compliance_reporting import pdf_report_as_bytes


@pytest.mark.asyncio
async def test_pdf_report_as_bytes(pg_compliance_config):
    # Arrange
    run_group_id = 1
    compliance_record_id = 1
    requester_id = 1  # admin user
    user_id = 2  # user performing runs
    async with generate_async_session(pg_compliance_config) as session:
        requester = (await session.execute(select(User).where(User.user_id == requester_id))).scalar_one()
        user = (await session.execute(select(User).where(User.user_id == user_id))).scalar_one()
        run_group = (await session.execute(select(RunGroup).where(RunGroup.run_group_id == run_group_id))).scalar_one()
        compliance_record = (
            await session.execute(
                select(ComplianceRecord).where(ComplianceRecord.compliance_record_id == compliance_record_id)
            )
        ).scalar_one()
        compliance_by_class = await get_compliance_for_run_group(
            procedure_map=await get_procedure_mapping(session, run_group)
        )

    print(f"{compliance_by_class["C"]}")
    # Act
    report = pdf_report_as_bytes(
        requester=requester,
        user=user,
        run_group=run_group,
        compliance_by_class=compliance_by_class,
        compliance_record=compliance_record,
    )

    # Assert
    assert len(report) > 0

    # Optional: Save and open the PDF
    import os
    import subprocess
    import tempfile
    import uuid

    with tempfile.NamedTemporaryFile(suffix=".pdf", prefix=f"report_{uuid.uuid4().hex[:8]}_", delete=False) as f:
        f.write(report)
        f.flush()
        print(f"Saved comprehensive PDF report: {os.path.basename(f.name)}")
        subprocess.run(["xdg-open", f.name])
