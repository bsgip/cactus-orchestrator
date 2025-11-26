from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from cactus_orchestrator.crud import select_run_group_for_user, select_user_from_run_group
from cactus_orchestrator.model import ComplianceRecord, User
from cactus_orchestrator.reporting.compliance import get_compliance_for_run_group, get_procedure_mapping
from cactus_orchestrator.reporting.compliance_reporting import pdf_report_as_bytes


@dataclass
class Artifact:
    file_data: bytes
    mime_type: str


async def generate_run_group_artifact(
    session: AsyncSession, run_group_id: int, requester: User, compliance_record: ComplianceRecord
) -> Artifact | None:

    # Get all the information required for the report
    user = await select_user_from_run_group(session=session, run_group_id=run_group_id)
    if user is None:
        raise Exception()
    run_group = await select_run_group_for_user(session=session, user_id=user.user_id, run_group_id=run_group_id)
    if run_group is None:
        raise Exception()

    compliance_by_class = await get_compliance_for_run_group(
        procedure_map=await get_procedure_mapping(session, run_group)
    )

    # Generate the report
    file_data = pdf_report_as_bytes(
        requester=requester,
        user=user,
        run_group=run_group,
        compliance_by_class=compliance_by_class,
        compliance_record=compliance_record,
    )

    if file_data is None:
        return None
    return Artifact(file_data=file_data, mime_type="application/pdf")
