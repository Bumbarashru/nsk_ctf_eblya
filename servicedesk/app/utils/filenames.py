from __future__ import annotations

import re


_CONTROL_CHARS = re.compile(r"[\x00-\x1f]")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class FilenameRejected(ValueError):
    pass


def normalise_export_name(raw: str) -> str:
    if not raw:
        raise FilenameRejected("Filename is required")
    if _CONTROL_CHARS.search(raw):
        raise FilenameRejected("Invalid characters in filename")

    candidate = raw.strip()
    if not candidate:
        raise FilenameRejected("Filename is required")
    if "/" in candidate or "\\" in candidate:
        raise FilenameRejected("Path separators are not allowed")
    if ".." in candidate:
        raise FilenameRejected("Relative path segments are not allowed")
    if not _SAFE_NAME.fullmatch(candidate):
        raise FilenameRejected("Filename contains unsupported characters")
    return candidate
