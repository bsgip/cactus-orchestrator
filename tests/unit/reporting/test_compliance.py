import pytest
from assertical.fake.generator import generate_class_instance

from cactus_orchestrator.model import ComplianceRequest, Run, ComplianceRequestClass, ComplianceRequestRun
from cactus_orchestrator.reporting.compliance import determine_compliance, is_compliant


@pytest.mark.parametrize(
    "compliance_runs, required_test_procedures, expected_result",
    [
        ({}, {"ALL-01"}, False),
        ({"ALL-01": generate_class_instance(Run, all_criteria_met=False)}, {"ALL-01"}, False),
        ({"ALL-01": generate_class_instance(Run, all_criteria_met=True)}, {"ALL-01"}, True),
        (
            {
                "ALL-01": generate_class_instance(Run, all_criteria_met=True),
                "ALL-02": generate_class_instance(Run, all_criteria_met=False),
            },
            {"ALL-01", "ALL-02"},
            False,
        ),
        (
            {
                "ALL-01": generate_class_instance(Run, all_criteria_met=True),
                "ALL-03": generate_class_instance(Run, all_criteria_met=True),
            },
            {"ALL-01", "ALL-02"},
            False,
        ),
    ],
)
def test_is_compliant(compliance_runs: dict[str, Run], required_test_procedures: set[str], expected_result: bool):
    assert (
        is_compliant(compliance_runs=compliance_runs, required_test_procedures=required_test_procedures)
        == expected_result
    )


def test_determine_compliance():
    # Arrange
    expected_classes = ["A"]
    expected_excluded_classes = [
        "C",
        "DER-A",
        "DER-A-ALT",
        "DER-G",
        "DER-L",
        "DER-L-ALT",
        "DR-A",
        "DR-D",
        "DR-G",
        "DR-L",
        "G",
        "L",
        "M",
        "P-A",
        "S-G",
        "S-L",
    ]
    class_A_test_procedures = [
        "ALL-01",
        "ALL-02",
        "ALL-03-REJ",
        "ALL-04",
        "ALL-05",
        "ALL-06",
        "ALL-07",
        "ALL-08",
        "ALL-09",
        "ALL-10",
        "ALL-11",
        "ALL-12",
        "ALL-13",
        "ALL-18",
        "ALL-19",
        "ALL-20",
        "ALL-21",
        "ALL-22",
        "ALL-23",
        "ALL-24",
        "ALL-25",
        "ALL-25-EXT",
    ]
    expected_compliance_runs = {
        tp: generate_class_instance(Run, testprocedure_id=tp, all_criteria_met=True) for tp in class_A_test_procedures
    }
    compliance_request = generate_class_instance(
        ComplianceRequest,
        file_data=b"",
        csip_aus_version="v1.2",
        classes={generate_class_instance(ComplianceRequestClass, compliance_class="A")},
        runs={
            generate_class_instance(ComplianceRequestRun, compliance_run=expected_compliance_runs[tp])
            for tp in class_A_test_procedures
        },
    )

    # Act
    classes, excluded_classes, class_to_test_procedures, compliance_runs = determine_compliance(
        compliance_request=compliance_request
    )

    # Assert
    assert classes == expected_classes
    assert excluded_classes == expected_excluded_classes
    assert compliance_runs == expected_compliance_runs

    # Repeat but have compliance test have 1 missing run and 1 failed run that would
    # be required to meet compliance class A
    expected_classes = []
    expected_excluded_classes.insert(0, "A")

    MISSING_RUN = "ALL-25-EXT"
    del expected_compliance_runs[MISSING_RUN]

    FAILED_RUN = "ALL-25"
    del expected_compliance_runs[FAILED_RUN]

    submitted_runs = expected_compliance_runs.copy()
    submitted_runs[FAILED_RUN] = generate_class_instance(Run, testprocedure_id=FAILED_RUN, all_criteria_met=False)
    compliance_request = generate_class_instance(
        ComplianceRequest,
        file_data=b"",
        csip_aus_version="v1.2",
        classes={generate_class_instance(ComplianceRequestClass, compliance_class="A")},
        runs={
            generate_class_instance(ComplianceRequestRun, compliance_run=submitted_runs[tp]) for tp in submitted_runs
        },
    )

    # Act
    classes, excluded_classes, class_to_test_procedures, compliance_runs = determine_compliance(
        compliance_request=compliance_request
    )

    # Assert
    assert classes == expected_classes
    assert excluded_classes == expected_excluded_classes
    assert compliance_runs == expected_compliance_runs
