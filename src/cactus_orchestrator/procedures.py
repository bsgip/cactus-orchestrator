from cactus_test_definitions.client import get_all_test_procedures
from cactus_test_definitions.client.test_procedures import TestProcedure, TestProcedureId

from cactus_orchestrator.settings import get_current_settings


def get_filtered_test_procedures() -> dict[TestProcedureId, TestProcedure]:
    ignored = set(get_current_settings().ignored_test_procedures)
    return {k: v for k, v in get_all_test_procedures().items() if k.value not in ignored}
