import pytest
from assertical.fixtures.postgres import generate_async_session
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from cactus_orchestrator.crud import upsert_user, insert_user
from cactus_orchestrator.k8s.certificate.create import generate_client_p12
from cactus_orchestrator.schema import UserContext


@pytest.mark.asyncio
async def test_add_user(pg_empty_conn, ca_cert_key_pair):
    """basic success test"""
    # Arrange
    ca_cert, ca_key = ca_cert_key_pair
    cl_p12, cl_x509 = generate_client_p12(ca_key, ca_cert, "test", "abc")
    cl_der = cl_x509.public_bytes(encoding=serialization.Encoding.DER)
    uc = UserContext(subject_id="a", issuer_id="a")

    # Act
    async with generate_async_session(pg_empty_conn.connection) as s:
        user = await insert_user(s, uc, cl_p12, cl_der)

    # Assert
    assert user.user_id == 1
    assert user.certificate_p12_bundle == cl_p12
    assert user.certificate_x509_der == cl_der
    assert user.subject_id == uc.subject_id
    assert user.issuer_id == uc.issuer_id


@pytest.mark.asyncio
async def test_add_or_update_user_unique_constraint(pg_empty_conn, ca_cert_key_pair):
    """test exception raised on unique constraint breach"""
    # Arrange
    ca_cert, ca_key = ca_cert_key_pair
    cl_p12, cl_x509 = generate_client_p12(ca_key, ca_cert, "test", "abc")
    cl_der = cl_x509.public_bytes(encoding=serialization.Encoding.DER)
    uc = UserContext(subject_id="a", issuer_id="a")

    async with generate_async_session(pg_empty_conn.connection) as s:
        _ = await insert_user(s, uc, cl_p12, cl_der)
        await s.commit()

    with pytest.raises(IntegrityError):
        async with generate_async_session(pg_empty_conn.connection) as s:
            _ = await insert_user(s, uc, cl_p12, cl_der)
            await s.commit()


@pytest.mark.asyncio
async def test_add_or_update_user(pg_empty_conn, ca_cert_key_pair):
    """Create a user, then update their certs"""
    # Arrange
    ca_cert, ca_key = ca_cert_key_pair
    cl_p12, cl_x509 = generate_client_p12(ca_key, ca_cert, "test", "abc")
    cl_der = cl_x509.public_bytes(encoding=serialization.Encoding.DER)
    uc = UserContext(subject_id="a", issuer_id="a")

    async with generate_async_session(pg_empty_conn.connection) as s:
        _ = await insert_user(s, uc, cl_p12, cl_der)
        await s.commit()

    cl_p12, cl_x509 = generate_client_p12(ca_key, ca_cert, "test1", "abc")
    cl_der = cl_x509.public_bytes(encoding=serialization.Encoding.DER)
    # Act
    async with generate_async_session(pg_empty_conn.connection) as s:
        await upsert_user(s, uc, cl_p12, cl_der)
        await s.commit()
    # Assert
    cert_x509_der = pg_empty_conn.execute(text("select certificate_x509_der from users;")).fetchone()[0]
    cert_x509 = x509.load_der_x509_certificate(cert_x509_der)
    assert cert_x509.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "test1"
