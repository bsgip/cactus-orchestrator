import os
import shutil
import tempfile
from collections.abc import Generator
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from cactus_orchestrator.teststack.manager import PodmanTeststackManager
from tests.integration import MockedTeststack


@pytest.fixture
def k8s_mock() -> Generator[MockedTeststack, None, None]:
    with (
        patch.object(PodmanTeststackManager, "spawn", new_callable=AsyncMock) as mock_spawn,
        patch.object(PodmanTeststackManager, "destroy", new_callable=AsyncMock) as mock_destroy,
        patch("cactus_orchestrator.api.run.RunnerClient.initialise") as init,
        patch("cactus_orchestrator.api.run.RunnerClient.start") as start,
        patch("cactus_orchestrator.api.run.RunnerClient.finalize") as finalize,
        patch("cactus_orchestrator.api.run.RunnerClient.status") as status,
        patch("cactus_orchestrator.api.run.RunnerClient.last_interaction") as last_interaction,
        patch("cactus_orchestrator.api.run.RunnerClient.health") as health,
        patch("cactus_orchestrator.api.run.RunnerClient.list_requests") as list_requests,
        patch("cactus_orchestrator.api.run.RunnerClient.get_request") as get_request,
        patch("cactus_orchestrator.api.run.RunnerClient.proceed") as proceed,
    ):
        # spawn returns proper resource names (computed from settings) so URL assertions pass
        async def spawn_side_effect(teststack_id, csip_aus_version, user_name):
            return PodmanTeststackManager().get_resource_names(teststack_id)

        mock_spawn.side_effect = spawn_side_effect

        yield MockedTeststack(
            spawn=mock_spawn,
            destroy=mock_destroy,
            init=init,
            start=start,
            finalize=finalize,
            status=status,
            last_interaction=last_interaction,
            health=health,
            list_requests=list_requests,
            get_request=get_request,
            proceed=proceed,
        )


@pytest.fixture
def zip_file_data(reporting_data_json, reporting_data_version) -> bytes:
    json_reporting_data = reporting_data_json

    # Work in a temporary directory
    with tempfile.TemporaryDirectory() as tempdirname:
        base_path = Path(tempdirname)

        # All the test procedure artifacts should be placed in `archive_dir` to be archived
        archive_dir = base_path / "archive"
        os.mkdir(archive_dir)

        # Create reporting data json file
        if json_reporting_data is not None:
            file_path = archive_dir / f"ReportingData_v{reporting_data_version}.json"
            with open(file_path, "w") as f:
                f.write(json_reporting_data)

        # Create the temporary zip file
        ARCHIVE_BASEFILENAME = "finalize"
        ARCHIVE_KIND = "zip"
        shutil.make_archive(str(base_path / ARCHIVE_BASEFILENAME), ARCHIVE_KIND, archive_dir)

        # Read the zip file contents as binary
        archive_path = base_path / f"{ARCHIVE_BASEFILENAME}.{ARCHIVE_KIND}"
        with open(archive_path, mode="rb") as f:
            zip_contents = f.read()
    return zip_contents
