from unittest.mock import AsyncMock, Mock, patch
import pytest
import base64
import json

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key, Encoding, PrivateFormat, NoEncryption
from jose import jwt
from fastapi_cache import FastAPICache
from fastapi_cache.backends.inmemory import InMemoryBackend


from cactus.harness_orchestrator.auth import JWTValidator, JWTClaims, CactusAuthException

# init for tests
FastAPICache.init(InMemoryBackend())


@pytest.fixture
def jwt_validator():
    return JWTValidator()


@pytest.fixture
def jwks_response_stub():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    kid = "test-kid"
    public_numbers = public_key.public_numbers()
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": kid,
                "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes(256, "big")).decode("utf-8").rstrip("="),
                "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes(3, "big")).decode("utf-8").rstrip("="),
            }
        ]
    }
    return kid, jwks, private_key


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
@patch("cactus.harness_orchestrator.auth.httpx.AsyncClient")
async def test_fetch_rsa_jwks(mock_httpx_client_cls, jwt_validator, jwks_response_stub):
    # Arrange
    kid, jwks, _ = jwks_response_stub
    mock_httpx_client_inst = AsyncMock()
    mock_httpx_client_cls.return_value.__aenter__.return_value = mock_httpx_client_inst
    mock_httpx_client_inst.get = AsyncMock(return_value=Mock())
    mock_httpx_client_inst.get.return_value.json.return_value = jwks

    # Act
    res = await jwt_validator._fetch_rsa_jwks("http://fake-jwks-url")

    # Assert
    assert kid in res
    assert isinstance(load_pem_public_key(res[kid].encode("utf-8")), rsa.RSAPublicKey)


@pytest.mark.asyncio
@patch("cactus.harness_orchestrator.auth.httpx.AsyncClient")
async def test_get_pubkey(mock_httpx_client_cls, jwt_validator, jwks_response_stub):
    # Arrange
    kid, jwks, _ = jwks_response_stub
    mock_httpx_client_inst = AsyncMock()
    mock_httpx_client_cls.return_value.__aenter__.return_value = mock_httpx_client_inst
    mock_httpx_client_inst.get = AsyncMock(return_value=Mock())
    mock_httpx_client_inst.get.return_value.json.return_value = jwks

    # Act
    res = await jwt_validator.get_pubkey(kid)

    # Assert
    assert isinstance(res, rsa.RSAPublicKey)


@pytest.mark.asyncio
@patch("cactus.harness_orchestrator.auth.httpx.AsyncClient")
async def test_verify_jwt(mock_httpx_client_cls, jwt_validator, jwks_response_stub):
    # Arrange
    kid, jwks, private_key = jwks_response_stub
    mock_httpx_client_inst = AsyncMock()
    mock_httpx_client_cls.return_value.__aenter__.return_value = mock_httpx_client_inst
    mock_httpx_client_inst.get = AsyncMock(return_value=Mock())
    mock_httpx_client_inst.get.return_value.json.return_value = jwks
    claims = {
        "sub": "user123",
        "aud": "cactus-orchestrator",
        "iss": "auth-server",
        "exp": 9999999999,
        "iat": 1700000000,
        "scopes": "user:read user:create",
    }
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    token = jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": kid})
    jwt_validator._settings.jwtauth_issuer = "auth-server"

    # Act
    res = await jwt_validator.verify_jwt(token)

    # Assert
    assert isinstance(res, JWTClaims)
    assert res.sub == "user123"
    assert "user:create" in res.scopes


@pytest.mark.asyncio
async def test_check_scopes_success(jwt_validator):
    # Arrange
    claims = JWTClaims(
        sub="user123",
        aud="cactus-orchestrator",
        iss="auth-server",
        exp=9999999999,
        iat=1700000000,
        scopes={"user:all"},
    )

    # Act
    res = jwt_validator._check_scopes({"user:all"}, claims)

    # Assert
    assert res == claims


@pytest.mark.asyncio
async def test_check_scopes_fail(jwt_validator):
    claims = JWTClaims(
        sub="user123",
        aud="cactus-orchestrator",
        iss="auth-server",
        exp=9999999999,
        iat=1700000000,
        scopes={"user:all"},
    )
    with pytest.raises(CactusAuthException, match="Insufficient scope permissions"):
        jwt_validator._check_scopes({"admin:all"}, claims)
