from sqlalchemy.ext.asyncio import AsyncSession
from cryptography import x509
from cryptography.hazmat.primitives import serialization


from cactus_orchestrator.cache import AsyncCache, ExpiringValue
from cactus_orchestrator.crud import select_user, upsert_user
from cactus_orchestrator.k8s.certificate.create import generate_client_p12
from cactus_orchestrator.k8s.certificate.fetch import fetch_certificate_key_pair, fetch_certificate_only
from cactus_orchestrator.schema import UserContext
from cactus_orchestrator.settings import TEST_CLIENT_P12_PASSWORD, CactusOrchestratorException, main_settings


async def update_ca_certificate_cache(_: Any) -> dict[str, ExpiringValue[x509.Certificate]]:
    cert = await fetch_certificate_only(main_settings.tls_ca_certificate_generic_secret_name)

    return {_ca_crt_cachekey: ExpiringValue(expiry=cert.not_valid_after_utc, value=cert)}


# NOTE: do not log.
_ca_crt_cachekey = ""
_ca_crt_cache = AsyncCache(update_fn=update_ca_certificate_cache, force_update_delay_seconds=60)


class CertificateManager:

    @staticmethod
    async def _create_client_cert_binary(user_context: UserContext) -> tuple[bytes, bytes]:
        ca_cert, ca_key = await fetch_certificate_key_pair(main_settings.tls_ca_tls_secret_name)  # TODO: cache maybe?

        # create client certificate
        client_p12, client_cert = generate_client_p12(
            ca_cert=ca_cert,
            ca_key=ca_key,
            client_common_name=user_context.subject_id,
            p12_password=TEST_CLIENT_P12_PASSWORD.get_secret_value(),
        )
        return client_p12, client_cert.public_bytes(encoding=serialization.Encoding.DER)

    @staticmethod
    async def fetch_current_certificate_authority_der() -> x509.Certificate:
        # fetch ca
        ca_cert = await _ca_crt_cache.get_value(None, _ca_crt_cachekey)

        if ca_cert is None:
            raise CactusOrchestratorException("CA certificate not found.")

        return ca_cert

    @classmethod
    async def create_user_certificate(
        cls,
        session: AsyncSession,
        user_context: UserContext,
    ) -> bytes:
        # create certs
        client_p12, client_x509_der = await cls._create_client_cert_binary(user_context)

        # insert or update user with new cert
        _ = await upsert_user(session, user_context, client_p12=client_p12, client_x509_der=client_x509_der)

        await session.commit()

        return client_p12

    @staticmethod
    async def fetch_existing_certificate_p12(
        session: AsyncSession,
        user_context: UserContext,
    ) -> bytes:

        # get user with p12
        user = await select_user(session, user_context, with_p12=True)

        if user is None:
            raise CactusOrchestratorException("No client certificate has been registed")

        return user.certificate_p12_bundle
