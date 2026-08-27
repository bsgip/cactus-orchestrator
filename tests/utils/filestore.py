from cactus_orchestrator.filestore import save_run_finalisation, save_run_report
from cactus_orchestrator.settings import get_current_settings


def load_file_store_for_test(
    run_id: int,
    finalisation_zip_bytes: bytes | None = None,
    existing_report_bytes: bytes | None = None,
) -> None:
    """Loads the filestore for a particular run with the specified values"""
    settings = get_current_settings()

    # Write zip data
    if finalisation_zip_bytes:
        save_run_finalisation(settings.file_store_path, run_id, finalisation_zip_bytes)

    # Write report data
    if existing_report_bytes is not None:
        save_run_report(settings.file_store_path, run_id, existing_report_bytes)
