from datetime import datetime
from enum import IntEnum, auto

from sqlalchemy import BOOLEAN, DateTime, ForeignKey, Index, Integer, LargeBinary, String, UniqueConstraint, desc, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


UserUniqueConstraintName = "subject_id_issuer_id_key"


class User(Base):
    """Store for users and their global configuration options"""

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
    user_name: Mapped[str] = mapped_column(String, nullable=True)

    subscription_domain: Mapped[str | None] = mapped_column(
        String, nullable=True
    )  # What FQDN is allowed to be subscribed
    is_static_uri: Mapped[bool] = mapped_column(
        BOOLEAN, server_default="0"
    )  # If True - always use the same URI for all spawned instances (this will limit them to a single run at a time)
    pen: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )  # 0 is the only reserved PEN so can be used as the NULL value.

    run_groups: Mapped[list["RunGroup"]] = relationship(lazy="raise", back_populates="user")


class RunReportGeneration(Base):
    """A RunReportGeneration records each time the RunArtifact is updated with a newly
    generated pdf report (generated from the reporting_data held in the RunArtifact table.
    """

    __tablename__ = "run_report_generation"

    run_report_generation_id: Mapped[int] = mapped_column(
        name="id", primary_key=True, autoincrement=True
    )  # primary key
    run_artifact_id: Mapped[int] = mapped_column(
        ForeignKey("run_artifact.id")
    )  # The run artifact that was (re)generated
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class RunGroup(Base):
    """A RunGroup is so users can organise their runs under the label of a specific device/client. Contains the TLS
    certs that will be utilised by runs under this group. Contains some settings that are unique to all runs in this
    group."""

    __tablename__ = "run_group"
    __table_args__ = (
        Index(
            "run_group_user_id_idx",
            "user_id",
            "id",
        ),
    )

    run_group_id: Mapped[int] = mapped_column(name="id", primary_key=True, autoincrement=True)  # primary key
    user_id: Mapped[int] = mapped_column(ForeignKey("user_.id"))  # User who owns this group

    name: Mapped[str] = mapped_column(String, nullable=False)  # descriptive name
    csip_aus_version: Mapped[str] = mapped_column(
        String, nullable=False
    )  # What test cases are used in this group - should be treated as immutable
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    is_device_cert: Mapped[bool | None] = mapped_column(
        BOOLEAN, nullable=True
    )  # If True - certificate_pem/key_pem represents a device certificate. Otherwise it's a aggregator certificate
    certificate_pem: Mapped[bytes | None] = mapped_column(
        LargeBinary, nullable=True, unique=False, deferred=True
    )  # PEM encoded - Aggregator certificate (the certificate bundled in the aggregator_certificate_p12_bundle)
    certificate_generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    certificate_id: Mapped[int] = mapped_column(
        Integer, server_default="0"
    )  # This is a "best effort" counter - can be subject to race conditions

    runs: Mapped[list["Run"]] = relationship(lazy="raise", back_populates="run_group")
    user: Mapped["User"] = relationship(lazy="raise")


class RunStatus(IntEnum):
    initialised = auto()
    started = auto()
    finalised_by_client = auto()  # Run has been terminated by client finalisation
    finalised_by_timeout = auto()  # Run has been terminated by timeout finalisation
    terminated = auto()  # Run was never explicitly finalised, shutdown somehow.
    provisioning = auto()  # Run has just been created - k8s services will be started next.
    skipped = auto()  # Run was skipped (e.g., playlist started from a later index)


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
            "run_group_id_run_status_idx",
            "run_group_id",
            "run_status",
        ),
        Index(
            "run_group_id_testprocedure_id_run_id_idx",
            "run_group_id",
            "testprocedure_id",
            desc("id"),
        ),
    )

    run_id: Mapped[int] = mapped_column(name="id", primary_key=True, autoincrement=True)
    run_group_id: Mapped[int] = mapped_column(ForeignKey("run_group.id"))
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
    is_device_cert: Mapped[bool] = mapped_column(
        BOOLEAN, server_default="0"
    )  # If True - this run was initialised using device certificate. Otherwise initialised using aggregator certificate

    # Playlist support - nullable for single-run executions
    playlist_execution_id: Mapped[str | None] = mapped_column(
        String, nullable=True, index=True
    )  # UUID linking runs in the same playlist execution
    playlist_order: Mapped[int | None] = mapped_column(Integer, nullable=True)  # 0-based order within the playlist

    run_artifact_id: Mapped[int | None] = mapped_column(ForeignKey("run_artifact.id"), nullable=True)
    run_artifact: Mapped["RunArtifact"] = relationship(lazy="raise")

    run_group: Mapped["RunGroup"] = relationship(lazy="raise")


class RunArtifact(Base):
    """Single compressed file composed of all run files"""

    __tablename__ = "run_artifact"

    run_artifact_id: Mapped[int] = mapped_column(name="id", primary_key=True, autoincrement=True)
    compression: Mapped[str] = mapped_column(String, nullable=False)
    file_data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False, unique=False)
    reporting_data: Mapped[str] = mapped_column(String, nullable=True, unique=False)


class ComplianceRecord(Base):
    """Records each instance a compliance report is generated for a run group."""

    __tablename__ = "compliance_record"

    compliance_record_id: Mapped[int] = mapped_column(name="id", primary_key=True, autoincrement=True)
    run_group_id: Mapped[int] = mapped_column(ForeignKey("run_group.id"))
    requester_id: Mapped[int] = mapped_column(
        ForeignKey("user_.id")
    )  # User who requested generation of the compliance report
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    file_data: Mapped[bytes] = mapped_column(LargeBinary, nullable=True, unique=False, deferred=True)
