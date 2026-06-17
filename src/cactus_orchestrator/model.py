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
    reporting_data: Mapped[str | None] = mapped_column(String, nullable=True, unique=False)
    version: Mapped[int | None] = mapped_column(Integer, nullable=True, unique=False)


class ComplianceRecord(Base):
    """Records each instance a compliance report is generated for a run group.

    Deprecated.
    This table recorded compliance on a per-run group basis and considered all
    runs in the run group to determine compliance.

    It was superceded by the ComplianceRequest table which holds
    - finalisation status in the 'status' column
    - compliance report in the 'file_data' column
    """

    __tablename__ = "compliance_record"

    compliance_record_id: Mapped[int] = mapped_column(name="id", primary_key=True, autoincrement=True)
    run_group_id: Mapped[int] = mapped_column(ForeignKey("run_group.id"))
    requester_id: Mapped[int] = mapped_column(
        ForeignKey("user_.id")
    )  # User who requested generation of the compliance report
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    file_data: Mapped[bytes] = mapped_column(LargeBinary, nullable=True, unique=False, deferred=True)


class ComplianceRequestStatus(IntEnum):
    """Encodes the status of a compliance request

    submitted    - client has created the request
                   admin has ability to open the request (see under_review)
                   client has ability to edit request
    under_review - once an admin opens a previously submitted request its status changes to 'under review'
                   admin has ability to edit the request
                   client can no longer edit the request
    pushed_back  - admin has pushed the request back to the client (changes needed)
                   admin can no longer edit the request
                   client has ability to edit the request
    finalised    - the compliance request is finalised (a compliance record gets created)
                   neither admin nor client can modify the request
    """

    SUBMITTED = auto()
    UNDER_REVIEW = auto()
    PUSHED_BACK = auto()
    FINALISED = auto()


class ComplianceRequest(Base):
    """Records each instance a compliance request made by a client

    Each compliance request records
    - A set of compliance classes to be assessed under.
    - A set of successful runs the cover the above compliance classes.
    - A collection of table metadata (e.g. created_at etc.)
    - A collection of compliance request metadata (e.g.
    """

    __tablename__ = "compliance_request"

    compliance_request_id: Mapped[int] = mapped_column(name="id", primary_key=True, autoincrement=True)

    # Table metadata
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    created_by: Mapped[int] = mapped_column(ForeignKey("user_.id"))  # the client(user) who requested compliance
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_by: Mapped[int] = mapped_column(
        ForeignKey("user_.id")
    )  # the last user to update the compliance request - could be the client or an admin
    created_by_user: Mapped[User] = relationship(foreign_keys=created_by, lazy="raise")
    updated_by_user: Mapped[User] = relationship(foreign_keys=updated_by, lazy="raise")

    # Status
    status: Mapped[ComplianceRequestStatus] = mapped_column(Integer, nullable=False)

    # Compliance classes
    classes: Mapped[set["ComplianceRequestClass"]] = relationship(lazy="raise", cascade="all, delete-orphan")
    runs: Mapped[set["ComplianceRequestRun"]] = relationship(lazy="raise", cascade="all, delete-orphan")

    # Compliance request metadata
    csip_aus_version: Mapped[str] = mapped_column(String, nullable=False, unique=False)
    witnessed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    der_brand: Mapped[str] = mapped_column(String, nullable=False, unique=False)
    der_oem: Mapped[str] = mapped_column(String, nullable=False, unique=False)
    der_series: Mapped[str] = mapped_column(String, nullable=False, unique=False)
    der_representative_models: Mapped[str] = mapped_column(String, nullable=False, unique=False)
    software_client_type: Mapped[str] = mapped_column(String, nullable=False, unique=False)
    software_client_providers: Mapped[str] = mapped_column(String, nullable=False, unique=False)
    software_client_versions: Mapped[str] = mapped_column(String, nullable=False, unique=False)
    onsite_hardware_details: Mapped[str] = mapped_column(String, nullable=False, unique=False)

    # Finalisation Report PDF file data
    file_data: Mapped[bytes] = mapped_column(LargeBinary, nullable=True, unique=False, deferred=True)


class ComplianceRequestClass(Base):
    """Many-to-one mapping from compliance_request to a set of compliance classes ("A", "DER-A" etc)"""

    __tablename__ = "compliance_request_class"

    compliance_request_class_id: Mapped[int] = mapped_column(name="id", primary_key=True, autoincrement=True)

    compliance_request_id: Mapped[int] = mapped_column(ForeignKey("compliance_request.id"))
    compliance_class: Mapped[str] = mapped_column(String, nullable=False, unique=False)


class ComplianceRequestRun(Base):
    """Many-to-one mapping from compliance request to a set of runs"""

    __tablename__ = "compliance_request_run"

    compliance_request_run_id: Mapped[int] = mapped_column(name="id", primary_key=True, autoincrement=True)

    compliance_request_id: Mapped[int] = mapped_column(ForeignKey("compliance_request.id"))
    compliance_run_id: Mapped[int] = mapped_column(ForeignKey("run.id"))
    compliance_run: Mapped[Run] = relationship(lazy="selectin")
