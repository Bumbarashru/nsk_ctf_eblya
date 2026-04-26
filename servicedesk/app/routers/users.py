from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import User
from utils.auth import get_current_user, has_support_access

router = APIRouter(prefix="/api/users", tags=["users"])


class ProfileUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    contact_phone: Optional[str] = Field(default=None, max_length=128)
    workspace: Optional[str] = None
    queue_scope: Optional[str] = None


@router.get("/me")
async def get_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "contact_phone": current_user.contact_phone,
        "role": current_user.role,
        "support_mode": has_support_access(current_user),
    }


@router.patch("/me")
async def update_profile(
    body: ProfileUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    data = body.model_dump(exclude_none=True)
    protected_fields = {"workspace", "queue_scope", "access_level"}
    attempted_protected = sorted(protected_fields.intersection(data.keys()))
    if attempted_protected:
        raise HTTPException(
            403,
            f"Changing protected profile fields is forbidden: {', '.join(attempted_protected)}",
        )

    if "username" in data:
        username = data["username"].strip()
        if not username:
            raise HTTPException(400, "Username cannot be empty")
        current_user.username = username

    if "email" in data:
        email = data["email"].strip()
        if not email:
            raise HTTPException(400, "Email cannot be empty")
        current_user.email = email

    if "contact_phone" in data:
        current_user.contact_phone = data["contact_phone"].strip()

    await db.commit()
    await db.refresh(current_user)

    return {
        "id": current_user.id,
        "username": current_user.username,
        "role": current_user.role,
        "workspace": current_user.workspace,
        "queue_scope": current_user.queue_scope,
        "contact_phone": current_user.contact_phone,
    }


@router.get("/{user_id}")
async def get_user(
    user_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not has_support_access(current_user) and current_user.id != user_id:
        raise HTTPException(403, "Forbidden")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "access_level": user.access_level,
        "workspace": user.workspace,
        "contact_phone": user.contact_phone,
    }


@router.get("")
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not has_support_access(current_user):
        raise HTTPException(403, "Forbidden")

    result = await db.execute(select(User))
    users = result.scalars().all()
    payload = []
    for u in users:
        entry = {
            "id": u.id,
            "username": u.username,
            "role": u.role,
            "access_level": u.access_level,
            "workspace": u.workspace,
            "contact_phone": u.contact_phone,
        }
        payload.append(entry)
    return payload
