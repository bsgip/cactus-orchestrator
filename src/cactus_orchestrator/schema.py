from datetime import datetime
from enum import StrEnum, auto

from cactus_test_definitions import TestProcedureId
from pydantic import BaseModel


class RunStatusResponse(StrEnum):
    initialised = auto()
    started = auto()
    finalised = auto()
    provisioning = auto()


class InitRunRequest(BaseModel):
    test_procedure_id: TestProcedureId


class StartRunResponse(BaseModel):
    test_url: str


class InitRunResponse(StartRunResponse):
    run_id: int


class RunResponse(BaseModel):
    run_id: int
    test_procedure_id: str
    test_url: str
    status: RunStatusResponse
    all_criteria_met: bool | None  # Whether this run has been assessed as successful or not (None means unknown)
    created_at: datetime
    finalised_at: datetime | None


class UserContext(BaseModel):
    """Model for validated user context"""

    subject_id: str
    issuer_id: str


class TestProcedureResponse(BaseModel):
    __test__ = False
    test_procedure_id: TestProcedureId
    description: str
    category: str


class TestProcedureRunSummaryResponse(BaseModel):
    __test__ = False
    test_procedure_id: TestProcedureId
    description: str
    category: str
    run_count: int  # Count of runs for this test procedure
    latest_all_criteria_met: bool | None  # Value for all_criteria_met of the most recent Run


class UserConfigurationRequest(BaseModel):
    subscription_domain: str  # What domain will outgoing notifications be scoped to?
    is_static_uri: bool  # If true - all test instances will share the same URI (limit to 1 test at a time)


class UserConfigurationResponse(UserConfigurationRequest):
    static_uri: str | None  # What the static URI will be for this user (readonly and only set if is_static_uri is True)
