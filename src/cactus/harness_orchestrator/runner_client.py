# TODO: this is currently just a stub / example
from enum import StrEnum
import httpx
from pydantic import BaseModel


class CsipAusTestProcedureCodes(StrEnum):
    ALL01 = "ALL-01"


class StartTestRequest(BaseModel):
    client_cert: str


# TODO: harness runner may need to expose two separate services, one for
# this orchestrator and other for proxying testing client requests.
class HarnessRunnerAsyncClient:
    def __init__(self, pod_fqdn: str, runner_port: int):
        self.url = httpx.URL("//" + pod_fqdn.lstrip("/"), scheme="http", port=runner_port)

    async def post_start_test(self, test_code: CsipAusTestProcedureCodes, body: StartTestRequest) -> bool:
        # TODO: logging, retries, exception handling
        try:
            _ = await httpx.post(
                self.url, json=body.model_dump_json(), params=httpx.QueryParams({"test": test_code.value}), timeout=30
            )
        except httpx.TimeoutException:
            return False
        return True
