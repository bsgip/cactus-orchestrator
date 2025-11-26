from collections import defaultdict
from dataclasses import dataclass
from enum import Enum, auto

from cactus_test_definitions.client import TestProcedureConfig, TestProcedureId
from sqlalchemy.ext.asyncio import AsyncSession

from cactus_orchestrator.crud import select_group_runs_aggregated_by_procedure
from cactus_orchestrator.model import RunGroup
from cactus_orchestrator.schema import TestProcedureRunSummaryResponse


class ComplianceStatus(Enum):
    ACTIVE = auto()
    RUNLESS = auto()
    SUCCESS = auto()
    FAILED = auto()
    UNKNOWN = auto()


@dataclass
class ComplianceClass:
    name: str
    description: str


@dataclass
class RunCompliance:
    run: TestProcedureRunSummaryResponse
    status: ComplianceStatus


@dataclass
class Compliance:
    class_details: ComplianceClass
    is_compliant: bool
    per_run_compliance: list[RunCompliance]


# This is an adapted version of TS 5573 Table 12.5 - Applicability of tests to classes of DER client
COMPLIANCE_CLASS_ORDERED: list[tuple[str, ComplianceClass]] = [
    ("A", ComplianceClass("A", "All clients managing DER (Excluding demand response).")),
    ("G", ComplianceClass("G", "Clients managing generation-type or storage-type DER.")),
    ("L", ComplianceClass("L", "Clients managing load-type or storage-type DER.")),
    ("C", ComplianceClass("C", "Clients conforming with the optional ConnectionPoint extension.")),
    ("S", ComplianceClass("S", "Clients implementing Subscription/Notification functionality.")),
    ("M", ComplianceClass("M", "Clients supporting management of sets of DER.")),
    ("DER-A", ComplianceClass("DER-A", "All DER.")),
    ("DER-G", ComplianceClass("DER-G", "All DER capable of generation.")),
    ("DER-L", ComplianceClass("DER-L", "All DER capable of consumption.")),
    ("DR-A", ComplianceClass("DR-A", "All clients managing demand response devices.")),
    ("DR-D", ComplianceClass("DR-D", "Clients managing or incorporated into DRED demand response devices.")),
    (
        "DR-L",
        ComplianceClass(
            "DR-L", "Clients managing load-type or storage-type products with demand response capabilities."
        ),
    ),
    (
        "DR-G",
        ComplianceClass(
            "DR-G", "Clients managing generation-type or storage-type products with demand response capabilities."
        ),
    ),
]


def fetch_compliance_classes(class_names: set[str]) -> list[ComplianceClass]:
    items: list[ComplianceClass] = []
    matched_keys: set[str] = set()

    for key, cc in COMPLIANCE_CLASS_ORDERED:
        if key in class_names:
            items.append(cc)
            matched_keys.add(key)

    # Now find anything leftover in class_names that we don't have a description for
    for class_name in class_names:
        if class_name not in matched_keys:
            items.append(ComplianceClass(class_name, ""))

    return items


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
    test_procedure_definitions = TestProcedureConfig.from_resource()

    procedures: list[TestProcedureRunSummaryResponse] = []
    for agg in await select_group_runs_aggregated_by_procedure(session=session, run_group_id=run_group.run_group_id):
        definition = test_procedure_definitions.test_procedures.get(agg.test_procedure_id.value, None)
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
