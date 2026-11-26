from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cactus_orchestrator.model import Certificate, RunGroup


async def assign_test_certificate(
    session: AsyncSession, run_group: RunGroup, certificate_pem: bytes, is_device_cert: bool | None = None
) -> Certificate:
    """Creates a new Certificate (owned by run_group's user) with certificate_pem and assigns it to run_group.

    If is_device_cert is None - the type of any existing assigned certificate will be reused (defaulting to device)"""
    if is_device_cert is None:
        existing_is_device_cert = None
        if run_group.certificate_id is not None:
            existing_is_device_cert = (
                await session.execute(
                    select(Certificate.is_device_cert).where(Certificate.certificate_id == run_group.certificate_id)
                )
            ).scalar_one()
        is_device_cert = True if existing_is_device_cert is None else existing_is_device_cert

    certificate = Certificate(
        user_id=run_group.user_id,
        name=f"test-cert-rg-{run_group.run_group_id}",
        is_device_cert=is_device_cert,
        certificate_pem=certificate_pem,
        generated_at=datetime.now(UTC),
        generation=1,
    )
    session.add(certificate)
    await session.flush()
    run_group.certificate_id = certificate.certificate_id
    return certificate
