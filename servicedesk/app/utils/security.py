from __future__ import annotations

import hmac
import ipaddress
import re
import unicodedata
from urllib.parse import urljoin, urlparse



class WebhookConfigError(ValueError):
    pass


def _is_blocked_webhook_host(hostname: str) -> bool:
    host = (hostname or "").strip().lower()
    if not host:
        return True

    if host in {"localhost", "host.docker.internal"}:
        return True
    if host.endswith(".localhost") or host.endswith(".local") or host.endswith(".internal"):
        return True

    try:
        ip = ipaddress.ip_address(host)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        # Single-label hosts such as "db" are treated as internal-only names.
        if "." not in host:
            return True
        return False


def validate_webhook_base(raw: str) -> str:
    if not raw or not isinstance(raw, str):
        raise WebhookConfigError("Base URL is required")
    stripped = raw.strip()
    if len(stripped) > 512:
        raise WebhookConfigError("Base URL too long")

    parsed = urlparse(stripped)
    if parsed.scheme not in ("http", "https"):
        if "://" not in stripped:
            raise WebhookConfigError("Base URL must start with http:// or https://")
        raise WebhookConfigError("Unsupported scheme for base URL")
    if not parsed.hostname:
        raise WebhookConfigError("Base URL must include a host")
    if parsed.username or parsed.password:
        raise WebhookConfigError("Credentials are not allowed in base URL")
    if _is_blocked_webhook_host(parsed.hostname):
        raise WebhookConfigError("Webhook target host is not allowed")

    return stripped


def validate_endpoint_path(raw: str) -> str:
    if raw is None:
        return ""
    if not isinstance(raw, str):
        raise WebhookConfigError("Endpoint path must be a string")
    path = raw.strip()
    if len(path) > 1024:
        raise WebhookConfigError("Endpoint path too long")
    lowered = path.lower()
    if lowered.startswith("http://") or lowered.startswith("https://"):
        raise WebhookConfigError("Endpoint path must be relative")
    return path


def resolve_webhook_target(base: str, path: str) -> str:
    return urljoin(base, path)


def normalise_filename_fragment(fragment: str) -> str:
    if fragment is None:
        return "attachment.bin"
    normalised = unicodedata.normalize("NFC", fragment)
    safe = re.compile(r"[^A-Za-z0-9._-]+").sub("_", normalised).strip("._")
    return safe or "attachment.bin"


def constant_time_equal(a: str, b: str) -> bool:
    if a is None or b is None:
        return False
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
