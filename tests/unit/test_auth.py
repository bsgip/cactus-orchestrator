import base64
import json
import os
from datetime import timedelta

import pytest
from assertical.fixtures.environment import environment_snapshot
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, load_pem_public_key
import jwt

from cactus_orchestrator.auth import JWTClaims, JWTValidator, JWTClaimsError

TEST_JWT_AUDIENCE = "my-audience"
TEST_JWT_ISSUER = "my.issuer"


@pytest.fixture
def jwt_validator():
    with environment_snapshot():
        os.environ["JWTAUTH_AUDIENCE"] = TEST_JWT_AUDIENCE
        os.environ["JWTAUTH_ISSUER"] = TEST_JWT_ISSUER
        yield JWTValidator(cache_length=timedelta(days=999))


def test_extract_kid_from_jwt(jwt_validator):
    # Arrange
    header = {"alg": "RS256", "typ": "JWT", "kid": "test-kid"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    token = f"{header_b64}.payload.signature"

    # Act
    res = jwt_validator._extract_kid_from_jwt(token)

    # Assert
    assert res == "test-kid"


@pytest.mark.asyncio
async def test_fetch_rsa_jwks(jwt_validator, kid_and_jwks_stub):
    # Arrange
    kid, _ = kid_and_jwks_stub

    # Act
    res = await jwt_validator._rsa_jwk_cache.get_value(None, kid)

    # Assert
    assert isinstance(load_pem_public_key(res.encode("utf-8")), rsa.RSAPublicKey)


@pytest.mark.asyncio
async def test_get_pubkey(jwt_validator, kid_and_jwks_stub):
    # Arrange
    kid, _ = kid_and_jwks_stub

    # Act
    res = await jwt_validator.get_pubkey(kid)

    # Assert
    assert isinstance(res, rsa.RSAPublicKey)


@pytest.mark.asyncio
async def test_verify_jwt(jwt_validator, kid_and_jwks_stub, ca_cert_key_pair):
    # Arrange
    kid, _ = kid_and_jwks_stub
    _, private_key = ca_cert_key_pair

    claims = {
        "sub": "user123",
        "aud": TEST_JWT_AUDIENCE,
        "iss": TEST_JWT_ISSUER,
        "exp": 9999999999,
        "iat": 1700000000,
        "scope": "user:read user:create",
    }
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    token = jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": kid})

    # Act
    res = await jwt_validator._verify_jwt(token)

    # Assert
    assert isinstance(res, JWTClaims)
    assert res.sub == "user123"
    assert "user:create" in res.scopes


@pytest.mark.asyncio
async def test_check_scopes_success(jwt_validator):
    # Arrange
    claims = JWTClaims(
        sub="user123",
        aud="cactus_orchestrator",
        iss="auth-server",
        exp=9999999999,
        iat=1700000000,
        scopes={"user:all"},
        permissions={"user:all"},
    )

    # Act
    res = jwt_validator._check_permissions({"user:all"}, claims)

    # Assert
    assert res == claims


@pytest.mark.asyncio
async def test_check_scopes_fail(jwt_validator):
    claims = JWTClaims(
        sub="user123",
        aud="cactus_orchestrator",
        iss="auth-server",
        exp=9999999999,
        iat=1700000000,
        scopes={"user:all"},
        permissions={"user:all"},
    )
    with pytest.raises(JWTClaimsError):
        jwt_validator._check_permissions({"admin:all"}, claims)
