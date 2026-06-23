from collections import defaultdict
from dataclasses import dataclass
from enum import Enum, auto

from cactus_schema.orchestrator import TestProcedureRunSummaryResponse
from cactus_schema.orchestrator.compliance import ComplianceClass, fetch_compliance_classes
from cactus_test_definitions.client import TestProcedure, TestProcedureId, get_all_test_procedures
from sqlalchemy.ext.asyncio import AsyncSession

from cactus_orchestrator.crud import select_group_runs_aggregated_by_procedure
from cactus_orchestrator.model import ComplianceRequest, Run, RunGroup
from cactus_orchestrator.procedures import get_filtered_test_procedures


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


ACTIVE_RUN_STATUSES = [1, 2, 6]  # initialized, started, provisioning
FINALIZED_RUN_STATUSES = [3, 4]  # finalized by user, finalized by timeout


def fetch_compliance_class(class_name: str) -> ComplianceClass:
    classes = fetch_compliance_classes({class_name})
    if classes:
        return classes[0]
    raise ValueError("Compliance class '{class_name}' not found.")


def run_summary_to_compliance_status(test_procedure: TestProcedureRunSummaryResponse) -> ComplianceStatus:
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
    test_procedure_definitions = get_filtered_test_procedures()

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


def is_compliant(
    compliance_runs: dict[str, Run],
    required_test_procedures: set[str],
) -> bool:
    compliant_test_procedures = set()
    for required_test_procedure in required_test_procedures:
        if required_test_procedure in compliance_runs and compliance_runs[required_test_procedure].all_criteria_met:
            compliant_test_procedures.add(required_test_procedure)

    return required_test_procedures == compliant_test_procedures


def determine_all_classes(csip_aus_version: str, test_procedures: dict[TestProcedureId, TestProcedure]) -> set[str]:
    all_classes = set()
    for v in test_procedures.values():
        if csip_aus_version in v.target_versions:
            all_classes.update(v.classes)
    return all_classes


def determine_class_to_test_procedure_mapping(
    csip_aus_version: str, test_procedures: dict[TestProcedureId, TestProcedure]
) -> dict[str, list[str]]:
    class_to_test_procedures = defaultdict(list)
    for name, t in test_procedures.items():
        if csip_aus_version in t.target_versions:
            for c in t.classes:
                class_to_test_procedures[c].append(name)
    for p in class_to_test_procedures.values():
        p.sort()
    return class_to_test_procedures


def determine_compliance_runs(runs: set[Run]) -> dict[str, Run]:
    compliance_runs = {}
    for run in runs:
        if run.all_criteria_met:
            compliance_runs[run.testprocedure_id] = run
    return compliance_runs


def determine_compliance(
    compliance_request: ComplianceRequest,
) -> tuple[list[str], list[str], dict[str, list[str]], dict[str, Run]]:
    """Determines compliance from a compliance request.

    Args:
        compliance_request: ComplianceRequest

    Returns:
        Tuple containing:
        - Sorted list of compliance classes
          (these have been checked for compliance so there may be fewer than in compliance request)
        - Sorted list of non-compliant classes
        - A mapping for all compliance classes (for a given csip aus version) to their respective TestProcedures
        - A dictionary mapping compliant test procedure names to their corresponding runs
          (only includes successful runs so there may be fewer than in the compliance request)
    """
    test_procedures = get_all_test_procedures()
    all_classes = determine_all_classes(
        csip_aus_version=compliance_request.csip_aus_version, test_procedures=test_procedures
    )
    class_to_test_procedures = determine_class_to_test_procedure_mapping(
        csip_aus_version=compliance_request.csip_aus_version, test_procedures=test_procedures
    )
    raw_runs = {r.compliance_run for r in compliance_request.runs}
    compliance_runs = determine_compliance_runs(runs=raw_runs)

    # Determine compliant classes (this performs a simple verification)
    compliant_classes = set()
    for c in compliance_request.classes:
        class_name = c.compliance_class
        if is_compliant(
            compliance_runs=compliance_runs,
            required_test_procedures=set(class_to_test_procedures[class_name]),
        ):
            compliant_classes.add(class_name)

    # Determine excluded classes (not met compliance requirements)
    noncompliant_classes = all_classes - compliant_classes

    return (
        sorted(list(compliant_classes)),
        sorted(list(noncompliant_classes)),
        class_to_test_procedures,
        compliance_runs,
    )
