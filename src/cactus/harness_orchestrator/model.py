from sqlalchemy import String, BINARY, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, validates


class Base(DeclarativeBase):
    pass


UserUniqueConstraintName = "subject_id_issuer_id_uc"


# TODO: track creation/expiry or make that 100% users problem?
class User(Base):
    """Store for users and their issued mTLS client certificates"""

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint(
            "subject_id",
            "issuer_id",
            name=UserUniqueConstraintName,
        ),
    )

    user_id: Mapped[int] = mapped_column(name="id", primary_key=True, autoincrement=True)
    subject_id: Mapped[str] = mapped_column(String, nullable=False)  # JWT sub
    issuer_id: Mapped[str] = mapped_column(String, nullable=False)  # JWT iss
    certifcate_p12_bundle: Mapped[bytes] = mapped_column(BINARY, nullable=False, unique=True)  # p12
    certificate_x509_der: Mapped[bytes] = mapped_column(BINARY, nullable=False, unique=True)  # x509 DER-encoded


# TODO: Run, RunStatus, anything else?
