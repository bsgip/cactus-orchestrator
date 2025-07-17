from datetime import datetime
from enum import IntEnum, auto

from sqlalchemy import BOOLEAN, DateTime, ForeignKey, Index, Integer, LargeBinary, String, UniqueConstraint, desc, func
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

    subscription_domain: Mapped[str | None] = mapped_column(
        String, nullable=True
    )  # What FQDN is allowed to be subscribed
    is_static_uri: Mapped[bool] = mapped_column(
        BOOLEAN, server_default="0"
    )  # If True - always use the same URI for all spawned instances (this will limit them to a single run at a time)

    runs: Mapped[list["Run"]] = relationship(lazy="raise")


class RunStatus(IntEnum):
    initialised = auto()
    started = auto()
    finalised_by_client = auto()  # Run has been terminated by client finalisation
    finalised_by_timeout = auto()  # Run has been terminated by timeout finalisation
    terminated = auto()  # Run was never explicitly finalised, shutdown somehow.
    provisioning = auto()  # Run has just been created - k8s services will be started next.


class Run(Base):
    __tablename__ = "run"
    __table_args__ = (
        Index(
            "run_status_created_at_testprocedure_id_idx",
            "run_status",
            "created_at",
            "testprocedure_id",
        ),
        Index(
            "user_id_run_status_idx",
            "user_id",
            "run_status",
        ),
        Index(
            "user_id_testprocedure_id_run_id_idx",
            "user_id",
            "testprocedure_id",
            desc("id"),
        ),
    )

    run_id: Mapped[int] = mapped_column(name="id", primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("user_.id"))
    teststack_id: Mapped[str] = mapped_column(
        String, nullable=False, index=True
    )  # We can't guarantee uniqueness as some users have "is_static_uri" set. Enforce uniqueness for running instances

    testprocedure_id: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    finalised_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    run_status: Mapped[RunStatus] = mapped_column(Integer, nullable=False)

    all_criteria_met: Mapped[bool | None] = mapped_column(
        BOOLEAN, nullable=True
    )  # True if EVERY criteria was met at run finalisation. False if there were issues. None if no data/still running

    run_artifact_id: Mapped[int] = mapped_column(ForeignKey("run_artifact.id"), nullable=True)
    run_artifact: Mapped["RunArtifact"] = relationship(lazy="raise")


class RunArtifact(Base):
    """Single compressed file composed of all run files"""

    __tablename__ = "run_artifact"

    run_artifact_id: Mapped[int] = mapped_column(name="id", primary_key=True, autoincrement=True)
    compression: Mapped[str] = mapped_column(String, nullable=False)
    file_data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False, unique=False)
