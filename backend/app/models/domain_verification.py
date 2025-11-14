"""Domain verification models for DNS TXT validation."""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field
from pydantic.config import ConfigDict
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.database import Base


class DomainVerificationStatus(str, Enum):
    """Possible statuses for domain verification lifecycle."""
    PENDING = "pending"
    VERIFIED = "verified"
    ERROR = "error"


class DomainVerification(Base):
    """SQLAlchemy model storing DNS TXT verification state per domain."""

    __tablename__ = "domain_verifications"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    host_label: Mapped[str] = mapped_column(String(512), nullable=False)
    token: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default=DomainVerificationStatus.PENDING.value)
    verification_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    last_checked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __table_args__ = (
        UniqueConstraint("user_id", "domain", name="uq_domain_verification_user_domain"),
    )


class DomainCreate(BaseModel):
    """Request payload for registering a domain for verification."""

    domain: str = Field(..., min_length=3, max_length=255)


class DomainResponse(BaseModel):
    """Serialized domain verification state."""

    id: str
    domain: str
    host_label: str
    token: str
    status: DomainVerificationStatus
    verification_attempts: int
    last_error: Optional[str]
    last_checked_at: Optional[datetime]
    verified_at: Optional[datetime]
    created_at: Optional[datetime]

    model_config = ConfigDict(from_attributes=True)


class DomainVerificationProfile(BaseModel):
    """Aggregated response describing account verification state."""

    verification_token: str
    host_prefix: str
    domains: list[DomainResponse]


class DomainVerificationResult(BaseModel):
    """Response after executing a verification attempt."""

    domain: DomainResponse
    message: str
    verified: bool
