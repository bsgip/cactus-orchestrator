import base64
import json
import logging
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from http import HTTPStatus
from typing import Any, Callable, Coroutine, cast

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import load_der_x509_certificate
from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import exceptions, jwt
from pydantic import BaseModel, ConfigDict

from cactus_orchestrator.cache import AsyncCache, ExpiringValue
from cactus_orchestrator.schema import UserContext
from cactus_orchestrator.settings import JWTAuthSettings

logger = logging.getLogger(__name__)

security = HTTPBearer()


class AuthPerm(StrEnum):
    user_all = "user:all"
    admin_all = "admin:all"


class JWTClaims(BaseModel):
    model_config = ConfigDict(extra="ignore")

    # NOTE: we use sub + iss to identify a unique user
    sub: str  # subject
    aud: str  # audience
    iss: str  # issuer
    exp: int  # expiry (unix epoch)
    iat: int | None  # issued at (unix epoch)
    scopes: set[str | None]  # set of strings or empty
    permissions: set[str]


class JWTValidator:
    cache_length: timedelta

    def __init__(self, cache_length: timedelta) -> None:
        self.cache_length = cache_length  # How long should the
        self._settings = JWTAuthSettings()  # type: ignore  [call-arg]
        self._rsa_jwk_cache = AsyncCache(self._update_rsa_jwk_cache, force_update_delay_seconds=10)

    def _reload_settings(self) -> None:
        """Not threadsafe / designed for normal - designed for tests to reload the settings. We will need to rework
        the depends/auth to support proper dependency injection to remove this cruft"""
        self._settings = JWTAuthSettings()  # type: ignore  [call-arg]

    async def _update_rsa_jwk_cache(self, _: Any) -> dict[str, ExpiringValue[str]]:
        """Fetchs a single JWK (RSA public key only) from the auth server.

        Returns:
            Dictionary of PEM-encoded RSAPublicKeys, keyed by KID (key identifier)
        """
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(self._settings.jwks_url)
                response.raise_for_status()
        except httpx.HTTPError as e:
            logger.error(f"Failed to update JWK cache. jwks_url={self._settings.jwks_url}", exc_info=e)
            raise exceptions.JWKError(f"Failed to fetch JWKS: {str(e)}")

        jwks = response.json().get("keys", [])
        now = datetime.now(tz=timezone.utc)
        cache_expiry = now + self.cache_length
        new_cache: dict[str, ExpiringValue[str]] = {}
        for key in jwks:
            if key["kty"].lower() == "rsa":
                rsa_key = self._deserialise_rsa_jwk(key)

                pem_key = rsa_key.public_bytes(
                    encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode(
                    "utf-8"
                )  # NOTE: deserialising here fore cache

                kid = key["kid"]
                logger.debug(f"JWK Cache entry update kid={kid} expiring={cache_expiry}")
                new_cache[kid] = ExpiringValue(now + self.cache_length, pem_key)

        if new_cache:
            logger.info(f"Updated JWK cache jwks_url={self._settings.jwks_url}. Found RSA kid's={new_cache.keys()}")
            return new_cache
        else:
            logger.error(f"No RSAPublicKey found for jwks_url={self._settings.jwks_url}")
            raise exceptions.JWKError("No RSAPublicKey found.")

    def _deserialise_rsa_jwk(self, jwk: dict[str, str]) -> rsa.RSAPublicKey:
        """We either get base64 url-encoded n/e and convert into an RSAPublicKey
        or base64-encoded x509, which we return RSAPublicKey of for consistency.
        """
        if "n" in jwk and "e" in jwk:
            # NOTE: these are url encoded too: https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1
            n = int.from_bytes(base64.urlsafe_b64decode(jwk["n"] + "=="), "big")
            e = int.from_bytes(base64.urlsafe_b64decode(jwk["e"] + "=="), "big")
            return rsa.RSAPublicNumbers(e, n).public_key()

        elif "x5c" in jwk:
            cert_der = base64.b64decode(jwk["x5c"][0])
            cert = load_der_x509_certificate(cert_der)
            return cast(rsa.RSAPublicKey, cert.public_key())

        raise exceptions.JWKError("JWK has invalid Form.")

    def _extract_kid_from_jwt(self, token: str) -> str:
        """Extract 'kid' from the JWT header."""
        header_b64 = token.split(".")[0]
        header_json = base64.urlsafe_b64decode(header_b64 + "==").decode("utf-8")
        header = json.loads(header_json)
        return header.get("kid")

    async def get_pubkey(self, kid: str) -> rsa.RSAPublicKey:
        """Get pubkey with using key-id"""
        rsa_pkey = await self._rsa_jwk_cache.get_value(None, kid)

        if rsa_pkey is None:
            logger.error(f"No matching key-id '{kid}' found in JWKs.")
            raise exceptions.JWKError(f"No matching key-id '{kid}' found in JWKs.")

        return cast(rsa.RSAPublicKey, serialization.load_pem_public_key(rsa_pkey.encode("utf-8")))

    async def _verify_jwt(self, token: str) -> JWTClaims:
        """Extract and verify JWT from Authorization header."""
        kid = self._extract_kid_from_jwt(token)
        logger.debug(f"Validating kid='{kid}'")

        public_key = await self.get_pubkey(kid)

        payload = jwt.decode(
            token,
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            algorithms=["RS256"],
            audience=self._settings.audience,
            issuer=self._settings.issuer,
        )

        scopes = set(payload.pop("scope", "").split())  # supposed to be space separated string of scopes
        permissions = set(payload.pop("permissions", []))  # permissions is a list
        return JWTClaims(**payload, scopes=scopes, permissions=permissions)

    def _check_permissions(self, required_permissions: set[str], jwt_claims: JWTClaims) -> JWTClaims:
        if not (required_permissions & jwt_claims.permissions):
            raise exceptions.JWTClaimsError("Insufficient permission")
        return jwt_claims

    def verify_jwt_and_check_perms(
        self, required_permissions: set[str]
    ) -> Callable[[HTTPAuthorizationCredentials], Coroutine[Any, Any, UserContext]]:
        """Wrap this method in Depends e.g. Depends(jwt_validator.verify_jwt_and_check_perms({"perm1"}))"""

        async def _verify_and_check_permissions(
            auth: HTTPAuthorizationCredentials = Security(security),
        ) -> UserContext:
            token = auth.credentials

            try:
                jwt_claims = await self._verify_jwt(token)
                validated = self._check_permissions(required_permissions, jwt_claims)
            except (exceptions.JWKError, exceptions.JWTClaimsError, exceptions.JWTError) as exc:
                logger.debug(
                    f"jwks_url='{self._settings.jwks_url}' issuer='{self._settings.issuer}' audience='{self._settings.audience}'"  # noqa: 501
                )
                logger.error(
                    f"Failure validating JWT claims. required_permissions={required_permissions}.",
                    exc_info=exc,
                )
                raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail="Invalid token")
            return UserContext(subject_id=validated.sub, issuer_id=validated.iss)

        return _verify_and_check_permissions


# NOTE: singleton
jwt_validator = JWTValidator(cache_length=timedelta(hours=4))
