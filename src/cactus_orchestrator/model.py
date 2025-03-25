from datetime import datetime
from enum import IntEnum

from sqlalchemy import DateTime, ForeignKey, LargeBinary, String, UniqueConstraint, func, Index, Integer
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


UserUniqueConstraintName = "subject_id_issuer_id_key"


class User(Base):
    """Store for users and their issued mTLS client certificates"""

    __tablename__ = "user_"
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

    # NOTE: We assume these are unique, too big to enfoce
    certificate_p12_bundle: Mapped[bytes] = mapped_column(
        LargeBinary, nullable=False, unique=False, deferred=True
    )  # p12
    certificate_x509_der: Mapped[bytes] = mapped_column(
        LargeBinary, nullable=False, unique=False, deferred=True
    )  # x509 DER-encoded

    runs: Mapped[list["Run"]] = relationship(lazy="raise")


class FinalisationStatus(IntEnum):
    not_finalised = 0  # Run is still alive
    by_client = 1  # Run has been terminated by client finalisation
    by_timeout = 2  # Run has been terminated by timeout finalisation
    terminated = 3  # Run was never explicitly finalised, shutdown somehow.


class Run(Base):
    __tablename__ = "run"
    __table_args__ = (
        Index(
            "finalisation_status_created_at_testprocedure_id_idx",
            "finalisation_status",
            "created_at",
            "testprocedure_id",
        ),
    )

    run_id: Mapped[int] = mapped_column(name="id", primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("user_.id"))
    teststack_id: Mapped[str] = mapped_column(String, nullable=False, unique=True, index=True)

    testprocedure_id: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    finalised_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    finalisation_status: Mapped[FinalisationStatus] = mapped_column(Integer, nullable=False)

    run_artifact_id: Mapped[int] = mapped_column(ForeignKey("run_artifact.id"), nullable=True)
    run_file: Mapped["RunArtifact"] = relationship(lazy="raise")


class RunArtifact(Base):
    """Single compressed file composed of all run files"""

    __tablename__ = "run_artifact"

    run_artifact_id: Mapped[int] = mapped_column(name="id", primary_key=True, autoincrement=True)
    compression: Mapped[str] = mapped_column(String, nullable=False)
    file_data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False, unique=False)
