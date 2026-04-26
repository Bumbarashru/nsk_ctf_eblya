from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from models import ShareToken


def _created_at_utc(share: ShareToken) -> datetime:
    created_at = share.created_at
    if created_at.tzinfo is None:
        return created_at.replace(tzinfo=timezone.utc)
    return created_at.astimezone(timezone.utc)


def build_share_token(case_number: str, audience: str = "external-review") -> str:
    return secrets.token_urlsafe(24)


def is_share_token_valid(share: ShareToken) -> bool:
    if not share.is_active:
        return False

    ttl = timedelta(hours=settings.share_token_ttl_hours)
    age = datetime.now(timezone.utc) - _created_at_utc(share)
    return age <= ttl


async def ensure_share_token(
    db: AsyncSession,
    ticket_id: str,
    created_by: str,
    case_number: str,
    audience: str = "external-review",
) -> ShareToken:
    result = await db.execute(
        select(ShareToken)
        .where(ShareToken.ticket_id == ticket_id)
        .where(ShareToken.is_active.is_(True))
        .order_by(ShareToken.created_at.desc())
    )
    share = result.scalar_one_or_none()
    if share and is_share_token_valid(share):
        return share

    if share and not is_share_token_valid(share):
        share.is_active = False

    token = build_share_token(case_number, audience)
    share = ShareToken(
        ticket_id=ticket_id,
        created_by=created_by,
        token=token,
    )
    db.add(share)
    await db.commit()
    await db.refresh(share)
    return share
