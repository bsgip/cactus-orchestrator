import os
import shutil
import tempfile
from pathlib import Path
from typing import Generator
from unittest.mock import patch

import pytest

from tests.integration import MockedK8s


@pytest.fixture
def k8s_mock() -> Generator[MockedK8s, None, None]:
    with (
        patch("cactus_orchestrator.api.run.add_ingress_rule") as add_ingress_rule,
        patch("cactus_orchestrator.api.run.clone_service") as clone_service,
        patch("cactus_orchestrator.api.run.clone_statefulset") as clone_statefulset,
        patch("cactus_orchestrator.api.run.wait_for_pod") as wait_for_pod,
        patch("cactus_orchestrator.api.run.delete_service") as delete_service,
        patch("cactus_orchestrator.api.run.delete_statefulset") as delete_statefulset,
        patch("cactus_orchestrator.api.run.remove_ingress_rule") as remove_ingress_rule,
        patch("cactus_orchestrator.api.run.RunnerClient.initialise") as init,
        patch("cactus_orchestrator.api.run.RunnerClient.start") as start,
        patch("cactus_orchestrator.api.run.RunnerClient.finalize") as finalize,
        patch("cactus_orchestrator.api.run.RunnerClient.status") as status,
        patch("cactus_orchestrator.api.run.RunnerClient.last_interaction") as last_interaction,
        patch("cactus_orchestrator.api.run.RunnerClient.health") as health,
        patch("cactus_orchestrator.api.run.RunnerClient.list_requests") as list_requests,
        patch("cactus_orchestrator.api.run.RunnerClient.get_request") as get_request,
    ):
        yield MockedK8s(
            add_ingress_rule=add_ingress_rule,
            clone_service=clone_service,
            clone_statefulset=clone_statefulset,
            wait_for_pod=wait_for_pod,
            delete_service=delete_service,
            delete_statefulset=delete_statefulset,
            remove_ingress_rule=remove_ingress_rule,
            init=init,
            start=start,
            finalize=finalize,
            status=status,
            last_interaction=last_interaction,
            health=health,
            list_requests=list_requests,
            get_request=get_request,
        )


@pytest.fixture
def zip_file_data() -> bytes:
    json_reporting_data = ""

    # Work in a temporary directory
    with tempfile.TemporaryDirectory() as tempdirname:
        base_path = Path(tempdirname)

        # All the test procedure artifacts should be placed in `archive_dir` to be archived
        archive_dir = base_path / "archive"
        os.mkdir(archive_dir)

        # Create reporting data json file
        if json_reporting_data is not None:
            file_path = archive_dir / f"ReportingData.json"
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
