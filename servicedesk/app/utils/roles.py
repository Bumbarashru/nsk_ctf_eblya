from __future__ import annotations

from typing import NamedTuple


class SeniorityBreakdown(NamedTuple):
    role_base: int
    workspace_adjust: int
    scope_adjust: int

    @property
    def total(self) -> int:
        return self.role_base + self.workspace_adjust + self.scope_adjust


SUPPORT_ACCESS_THRESHOLD = 3


def seniority_breakdown(user) -> SeniorityBreakdown:
    role = str(getattr(user, "role", "") or "").lower()
    role_base = 3 if role == "agent" else 1
    return SeniorityBreakdown(
        role_base=role_base,
        workspace_adjust=0,
        scope_adjust=0,
    )


def effective_seniority(user) -> int:
    return seniority_breakdown(user).total


def is_support_capable(user) -> bool:
    return effective_seniority(user) >= SUPPORT_ACCESS_THRESHOLD
