import re

from sqlalchemy import String, TypeDecorator, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, validates


class Base(DeclarativeBase):
    pass


# TODO: track creation/expiry or make that 100% users problem?
class User(Base):
    """Store for users and their issued mTLS client certificates"""

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint(
            "subject_id",
            "issuer_id",
            name="subject_id_issuer_id_uc",
        ),
    )

    user_id: Mapped[int] = mapped_column(name="id", primary_key=True, autoincrement=True)
    subject_id: Mapped[str] = mapped_column(String, nullable=False)  # JWT sub
    issuer_id: Mapped[str] = mapped_column(String, nullable=False)  # JWT iss
    certificate: Mapped[str] = mapped_column(String, nullable=False, unique=True)  # base64-encoded p12 certificate

    # email: Mapped[str] = mapped_column(LowercaseString, null  able=False)
    # @validates("email")
    # def validate_email(self, email):
    #     if not is_valid_email(email):
    #         raise ValueError(f"Invalid email: {email}")


# def is_valid_email(email):
#     pattern = r"^[\w.-]+@([\w-]+\.)+[\w-]{2,4}$"  # TODO: should we unlimit TLD length?
#     return bool(re.match(pattern, email))


# class LowercaseString(TypeDecorator):
#     impl = String

#     def process_bind_param(self, value, dialect):
#         return value.lower() if value else None


# TODO: Run, RunStatus, anything else?
