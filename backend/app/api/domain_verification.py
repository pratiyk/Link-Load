"""API endpoints for DNS TXT based domain verification."""
from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Callable
from urllib.parse import urlparse

import dns.exception
import dns.resolver
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import (
    DatabaseException,
    ResourceNotFoundException,
    ValidationException,
)
from app.core.security import get_current_user, security_manager
from app.database import get_db
from app.models.domain_verification import (
    DomainCreate,
    DomainResponse,
    DomainVerification,
    DomainVerificationProfile,
    DomainVerificationResult,
    DomainVerificationStatus,
)
from app.models.user import User
from app.utils.datetime_utils import utc_now

logger = logging.getLogger(__name__)
router = APIRouter(prefix=f"{settings.API_PREFIX}/domains", tags=["Domain Verification"])

_HOST_PREFIX = "_linkload"
_EXPECTED_RECORD_PREFIX = "linkload-site-verification="
_DOMAIN_REGEX = re.compile(r"[^a-z0-9.-]")


def _extract_user_id(user: User) -> str:
    user_id = getattr(user, "id", None)
    if not user_id:
        raise ValidationException("Authenticated user is missing an identifier.")
    return str(user_id)


def _sanitize_domain(raw_domain: str) -> str:
    """Normalize and validate domain values entered by users."""
    candidate = (raw_domain or "").strip().lower()
    if not candidate:
        raise ValidationException("Domain is required.")

    if "//" in candidate:
        parsed = urlparse(candidate, scheme="https")
        candidate = parsed.netloc or parsed.path

    candidate = candidate.split("/")[0]
    candidate = candidate.split("?")[0]
    candidate = candidate.strip().strip(".")
    candidate = _DOMAIN_REGEX.sub("-", candidate)
    candidate = re.sub(r"-+", "-", candidate)

    if not candidate or len(candidate) < 3:
        raise ValidationException("Provide a valid domain or subdomain.")

    if ".." in candidate or candidate.startswith("-") or candidate.endswith("-"):
        raise ValidationException("Domain contains invalid characters or formatting.")

    if len(candidate) > 253:
        raise ValidationException("Domain exceeds the maximum length supported by DNS.")

    return candidate


def _build_host_label(domain: str) -> str:
    return f"{_HOST_PREFIX}.{domain}"


def _expected_record(token: str) -> str:
    return f"{_EXPECTED_RECORD_PREFIX}{token}"


def _deserialize_preferences(user: User) -> dict:
    raw_preferences = getattr(user, "preferences", None)
    if not raw_preferences:
        return {}
    try:
        return json.loads(str(raw_preferences))
    except (json.JSONDecodeError, TypeError, ValueError):
        logger.warning("Invalid preference JSON for user %s; resetting", user.id)
        return {}


def _persist_preferences(db: Session, user: User, preferences: dict) -> None:
    setattr(user, "preferences", json.dumps(preferences))
    db.add(user)
    db.flush()


def _ensure_account_token(db: Session, user: User) -> str:
    preferences = _deserialize_preferences(user)
    token = preferences.get("verification_token")
    if not token:
        token = security_manager.generate_secure_token(24)
        preferences["verification_token"] = token
        _persist_preferences(db, user, preferences)
        db.commit()
        db.refresh(user)
    return token


def _sync_domain_tokens(domains: list[DomainVerification], token: str) -> bool:
    updated = False
    for domain in domains:
        if domain.token != token:
            domain.token = token
            # Do not downgrade verified domains unless rotated separately
            if domain.status != DomainVerificationStatus.VERIFIED.value:
                domain.status = DomainVerificationStatus.PENDING.value
            updated = True
    return updated


def _get_user_domain(db: Session, user_id: str, domain_id: str) -> DomainVerification:
    domain = (
        db.query(DomainVerification)
        .filter(
            DomainVerification.id == domain_id,
            DomainVerification.user_id == user_id,
        )
        .first()
    )
    if not domain:
        raise ResourceNotFoundException("Domain record not found")
    return domain


def _domain_to_response(domain: DomainVerification) -> DomainResponse:
    return DomainResponse.model_validate(domain, from_attributes=True)


def _async_dns_lookup(func: Callable[..., dns.resolver.Answer], *args, **kwargs):
    return asyncio.to_thread(func, *args, **kwargs)


async def _perform_dns_verification(domain: DomainVerification) -> tuple[bool, str]:
    """Query DNS for TXT records and validate the expected value."""
    host = domain.host_label
    expected_value = _expected_record(domain.token)

    try:
        answers = await _async_dns_lookup(
            dns.resolver.resolve,
            host,
            "TXT",
            lifetime=6,
            raise_on_no_answer=True,
        )
        records = list(answers)  # type: ignore[arg-type]
    except dns.resolver.NXDOMAIN:
        return False, f"No DNS zone found for {host}. Confirm the domain is spelled correctly."
    except dns.resolver.NoAnswer:
        return False, f"No TXT record present for {host}. Publish the verification record and try again."
    except dns.resolver.Timeout:
        return False, "DNS query timed out. Propagation may still be in progress."
    except dns.exception.DNSException as exc:
        logger.warning("DNS lookup failed for %s: %s", host, exc)
        return False, "Unexpected DNS lookup error while checking the TXT record."

    def _normalise_txt(rdata) -> str:
        parts = []
        for chunk in getattr(rdata, "strings", []) or []:
            if isinstance(chunk, bytes):
                parts.append(chunk.decode("utf-8", errors="ignore"))
            else:
                parts.append(str(chunk))
        if parts:
            return "".join(parts)
        text = str(rdata)
        return text.replace('"', "")

    for record in records:
        record_text = _normalise_txt(record).strip()
        if record_text == expected_value:
            return True, "TXT record verified successfully."

    return (
        False,
        "TXT record found but value does not match. Ensure it equals \"%s\"." % expected_value,
    )


@router.get("/profile", response_model=DomainVerificationProfile)
async def get_verification_profile(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DomainVerificationProfile:
    token = _ensure_account_token(db, current_user)
    user_id = _extract_user_id(current_user)
    domains = (
        db.query(DomainVerification)
        .filter(DomainVerification.user_id == user_id)
        .order_by(DomainVerification.created_at.asc())
        .all()
    )

    if _sync_domain_tokens(domains, token):
        db.commit()
        for domain in domains:
            db.refresh(domain)

    domain_responses = [_domain_to_response(domain) for domain in domains]
    return DomainVerificationProfile(
        verification_token=token,
        host_prefix=_HOST_PREFIX,
        domains=domain_responses,
    )


@router.post("", response_model=DomainResponse, status_code=status.HTTP_201_CREATED)
async def register_domain(
    payload: DomainCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DomainResponse:
    sanitized = _sanitize_domain(payload.domain)
    token = _ensure_account_token(db, current_user)
    host_label = _build_host_label(sanitized)
    user_id = _extract_user_id(current_user)

    existing = (
        db.query(DomainVerification)
        .filter(
            DomainVerification.user_id == user_id,
            DomainVerification.domain == sanitized,
        )
        .first()
    )

    if existing:
        existing.host_label = host_label
        if existing.token != token:
            existing.token = token
        existing.status = DomainVerificationStatus.PENDING.value
        existing.last_error = None
        existing.verified_at = None
        db.commit()
        db.refresh(existing)
        return _domain_to_response(existing)

    domain_record = DomainVerification(
        user_id=user_id,
        domain=sanitized,
        host_label=host_label,
        token=token,
        status=DomainVerificationStatus.PENDING.value,
    )

    try:
        db.add(domain_record)
        db.commit()
        db.refresh(domain_record)
    except Exception as exc:  # pragma: no cover - defensive logging
        db.rollback()
        logger.exception("Failed to register domain %s for user %s", sanitized, user_id)
        raise DatabaseException("Unable to register domain for verification right now.") from exc

    return _domain_to_response(domain_record)


@router.delete("/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_domain(
    domain_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    user_id = _extract_user_id(current_user)
    domain_record = _get_user_domain(db, user_id, domain_id)
    try:
        db.delete(domain_record)
        db.commit()
    except Exception as exc:  # pragma: no cover - defensive logging
        db.rollback()
        logger.exception("Failed to delete domain %s for user %s", domain_id, user_id)
        raise DatabaseException("Unable to remove domain at the moment.") from exc
    return None


@router.post("/{domain_id}/verify", response_model=DomainVerificationResult)
async def verify_domain(
    domain_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DomainVerificationResult:
    user_id = _extract_user_id(current_user)
    domain_record = _get_user_domain(db, user_id, domain_id)

    success, message = await _perform_dns_verification(domain_record)

    domain_record.verification_attempts += 1
    domain_record.last_checked_at = utc_now()

    if success:
        domain_record.status = DomainVerificationStatus.VERIFIED.value
        domain_record.verified_at = domain_record.last_checked_at
        domain_record.last_error = None
    else:
        if domain_record.status == DomainVerificationStatus.VERIFIED.value:
            domain_record.status = DomainVerificationStatus.ERROR.value
        else:
            domain_record.status = DomainVerificationStatus.PENDING.value
        domain_record.last_error = message

    db.commit()
    db.refresh(domain_record)

    return DomainVerificationResult(
        domain=_domain_to_response(domain_record),
        message=message,
        verified=success,
    )


@router.post("/rotate-token", response_model=DomainVerificationProfile)
async def rotate_verification_token(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DomainVerificationProfile:
    preferences = _deserialize_preferences(current_user)
    new_token = security_manager.generate_secure_token(24)
    preferences["verification_token"] = new_token
    user_id = _extract_user_id(current_user)

    domains = (
        db.query(DomainVerification)
        .filter(DomainVerification.user_id == user_id)
        .all()
    )

    for domain in domains:
        domain.token = new_token
        domain.status = DomainVerificationStatus.PENDING.value
        domain.verified_at = None
        domain.last_error = None
        domain.last_checked_at = None
        domain.verification_attempts = 0

    try:
        _persist_preferences(db, current_user, preferences)
        db.commit()
    except Exception as exc:  # pragma: no cover - defensive logging
        db.rollback()
        logger.exception("Unable to rotate verification token for user %s", user_id)
        raise DatabaseException("Failed to rotate verification token. Try again later.") from exc

    refreshed_domains = (
        db.query(DomainVerification)
        .filter(DomainVerification.user_id == user_id)
        .order_by(DomainVerification.created_at.asc())
        .all()
    )

    return DomainVerificationProfile(
        verification_token=new_token,
        host_prefix=_HOST_PREFIX,
        domains=[_domain_to_response(domain) for domain in refreshed_domains],
    )
