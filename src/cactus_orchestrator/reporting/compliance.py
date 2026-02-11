from collections import defaultdict
from dataclasses import dataclass
from enum import Enum, auto

from cactus_schema.orchestrator import TestProcedureRunSummaryResponse
from cactus_schema.orchestrator.compliance import ComplianceClass, fetch_compliance_classes
from cactus_test_definitions.client import TestProcedureId, get_all_test_procedures
from sqlalchemy.ext.asyncio import AsyncSession

from cactus_orchestrator.crud import select_group_runs_aggregated_by_procedure
from cactus_orchestrator.model import RunGroup


class ComplianceStatus(Enum):
    ACTIVE = auto()
    RUNLESS = auto()
    SUCCESS = auto()
    FAILED = auto()
    UNKNOWN = auto()


@dataclass
class RunCompliance:
    run: TestProcedureRunSummaryResponse
    status: ComplianceStatus


@dataclass
class Compliance:
    class_details: ComplianceClass
    is_compliant: bool
    per_run_compliance: list[RunCompliance]


def fetch_compliance_class(class_name: str) -> ComplianceClass:
    classes = fetch_compliance_classes({class_name})
    if classes:
        return classes[0]
    raise ValueError("Compliance class '{class_name}' not found.")


def run_summary_to_compliance_status(test_procedure: TestProcedureRunSummaryResponse) -> ComplianceStatus:
    ACTIVE_RUN_STATUSES = [1, 2, 6]  # initialized, started, provisioning
    FINALIZED_RUN_STATUSES = [3, 4]  # finalized by user, finalized by timeout

    if test_procedure.latest_run_status in ACTIVE_RUN_STATUSES:
        return ComplianceStatus.ACTIVE
    elif test_procedure.run_count == 0:
        return ComplianceStatus.RUNLESS
    elif test_procedure.latest_run_status in FINALIZED_RUN_STATUSES:
        if test_procedure.latest_all_criteria_met:
            return ComplianceStatus.SUCCESS
        else:
            return ComplianceStatus.FAILED
    else:
        return ComplianceStatus.UNKNOWN


async def get_class_compliance(
    compliance_class: str,
    tests: list[TestProcedureId],
    procedure_map: dict[TestProcedureId, TestProcedureRunSummaryResponse],
) -> Compliance:
    class_details = fetch_compliance_class(compliance_class)
    per_run_compliance = [
        RunCompliance(run=procedure_map[t], status=run_summary_to_compliance_status(procedure_map[t])) for t in tests
    ]
    is_compliant: bool = all([run.status == ComplianceStatus.SUCCESS for run in per_run_compliance])

    return Compliance(
        class_details=class_details,
        is_compliant=is_compliant,
        per_run_compliance=per_run_compliance,
    )


async def get_procedure_mapping(
    session: AsyncSession, run_group: RunGroup
) -> dict[TestProcedureId, TestProcedureRunSummaryResponse]:
    test_procedure_definitions = get_all_test_procedures()

    procedures: list[TestProcedureRunSummaryResponse] = []
    for agg in await select_group_runs_aggregated_by_procedure(session=session, run_group_id=run_group.run_group_id):
        definition = (
            test_procedure_definitions[agg.test_procedure_id]
            if agg.test_procedure_id in test_procedure_definitions
            else None
        )
        if definition and (run_group.csip_aus_version in definition.target_versions):
            procedures.append(
                TestProcedureRunSummaryResponse(
                    test_procedure_id=agg.test_procedure_id,
                    description=definition.description,
                    category=definition.category,
                    classes=definition.classes,
                    run_count=agg.count,
                    latest_all_criteria_met=agg.latest_all_criteria_met,
                    latest_run_status=agg.latest_run_status,
                    latest_run_id=agg.latest_run_id,
                    latest_run_timestamp=agg.latest_run_timestamp,
                )
            )
    procedure_map = {p.test_procedure_id: p for p in procedures}
    return procedure_map


async def get_compliance_for_run_group(
    procedure_map: dict[TestProcedureId, TestProcedureRunSummaryResponse],
) -> dict[str, Compliance]:

    tests_by_class = defaultdict(list)
    for p in procedure_map.values():
        if p.classes:
            for c in p.classes:
                tests_by_class[c].append(p.test_procedure_id)

    compliance_by_class: dict[str, Compliance] = {
        compliance_class: await get_class_compliance(compliance_class, tests, procedure_map)
        for compliance_class, tests in tests_by_class.items()
    }

    return compliance_by_class
