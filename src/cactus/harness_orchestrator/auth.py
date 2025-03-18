import base64
from enum import StrEnum
import json
from typing import Awaitable

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import load_der_x509_certificate
from pydantic import BaseModel
from fastapi_cache.decorator import cache
from fastapi import Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import httpx
from jose import jwt
from cryptography.hazmat.primitives import serialization

from cactus.harness_orchestrator.schema import UserContext
from cactus.harness_orchestrator.settings import JWTAuthSettings

security = HTTPBearer()


class CactusAuthScopes(StrEnum):
    user_all = "user:all"
    admin_all = "admin:all"


class JWTClaims(BaseModel):
    sub: str  # subject - user ID
    aud: str  # audience
    iss: str  # issuer
    exp: int  # expiry (unix epoch)
    iat: int  # issued at (unix epoch)
    scopes: set[str | None] = {}  # list of strings or empty


class CactusAuthException(Exception): ...  # noqa: E701


class JWTValidator:
    def __init__(self):
        self._settings = JWTAuthSettings()

    # TODO: better policy
    @cache(expire=3600)
    async def _fetch_rsa_jwks(self, jwks_url: str) -> dict[str, str]:
        """Fetch JWK (RSA public key only) from the auth server.

        Returns:
            Dictionary of PEM-encoded RSAPublicKeys, keyed by KID (key identifier)
        """
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(jwks_url)
                response.raise_for_status()
        except httpx.HTTPError as e:
            raise CactusAuthException(detail=f"Failed to fetch JWKS: {str(e)}")

        jwks = response.json().get("keys", [])
        for key in jwks:
            if key["kty"].lower() == "rsa":
                rsa_key = self._deserialise_rsa_jwk(key)

                pem_key = rsa_key.public_bytes(
                    encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode(
                    "utf-8"
                )  # NOTE: deserialising here fore cache
                return {key["kid"]: pem_key}
        raise CactusAuthException("No RSAPublicKey found.")

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
            return cert.public_key()

    def _extract_kid_from_jwt(self, token: str) -> str:
        """Extract 'kid' from the JWT header."""
        header_b64 = token.split(".")[0]
        header_json = base64.urlsafe_b64decode(header_b64 + "==").decode("utf-8")
        header = json.loads(header_json)
        return header.get("kid")

    async def get_pubkey(self, kid: str) -> rsa.RSAPublicKey:
        """Get pubkey with using key-id"""
        rsa_keys = await self._fetch_rsa_jwks(self._settings.jwtauth_jwks_url)
        rsa_pkey = rsa_keys.get(kid)

        if rsa_pkey is None:
            raise ValueError(f"No matching key-id '{kid}' found in JWKs.")

        return serialization.load_pem_public_key(rsa_pkey.encode("utf-8"))

    async def _verify_jwt(self, token: str) -> JWTClaims:
        """Extract and verify JWT from Authorization header."""
        kid = self._extract_kid_from_jwt(token)

        public_key = await self.get_pubkey(kid)
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=self._settings.jwtauth_audience,
            issuer=self._settings.jwtauth_issuer,
        )

        scopes = set(payload.pop("scopes", "").split())  # supposed to be space separated string of scopes
        return JWTClaims(**payload, scopes=scopes)

    def _check_scopes(self, required_scopes: set[str], jwt_claims: JWTClaims) -> JWTClaims:
        if not (required_scopes & jwt_claims.scopes):
            raise CactusAuthException("Insufficient scope permissions")
        return jwt_claims

    def verify_jwt_and_check_scopes(self, required_scopes: set[str]) -> Awaitable:
        """Wrap this method in Depends e.g. Depends(jwt_validator.verify_jwt_and_check_scopes({"scope1"}))"""

        async def _verify_and_check_scopes(
            auth: HTTPAuthorizationCredentials = Security(security),
        ) -> UserContext:
            token = auth.credentials
            jwt_claims = await self._verify_jwt(token)
            validated = self._check_scopes(required_scopes, jwt_claims)
            return UserContext(subject_id=validated.sub, issuer_id=validated.iss)

        return _verify_and_check_scopes


# NOTE: singleton
jwt_validator = JWTValidator()
