"""Shared helper utilities."""
from __future__ import annotations

import hashlib
import math
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from .constants import ENTROPY_MIN_LEN, ENTROPY_THRESHOLD


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _redact(text: str, keep: int = 6) -> str:
    if len(text) <= keep * 2:
        return "***"
    return f"{text[:keep]}…{text[-keep:]}"


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def _fingerprint(text: str) -> str:
    return _sha256(text)[:16]


def _chmod_private(path: Path, mode: int = 0o600) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _is_binary(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return b"\x00" in f.read(8192)
    except OSError:
        return True


def _is_redacted(value: str) -> bool:
    return "…" in value or value.startswith("***")


def _warn(message: str) -> None:
    print(f"Warning: {message}", file=sys.stderr)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


# Values that look like secrets to a regex but are code / fixtures / placeholders.
_FALSE_POSITIVE_VALUES = {
    "none",
    "null",
    "true",
    "false",
    "undefined",
    "password",
    "passwd",
    "secret",
    "token",
    "changeme",
    "change-me",
    "replace-me",
    "placeholder",
    "example",
    "dummy",
    "unused",
    "test",
    "testing",
    "sample",
    "todo",
    "xxxx",
    "yyyy",
    "postgres",
    "postgresql",
    "mysql",
    "redis",
    "mongodb",
    "admin",
    "root",
    "user",
    "username",
    "your-password",
    "your_password",
    "your-secret",
    "your_secret",
    "client_secret",
    "client-secret",
    "access_token",
    "refresh_token",
    "bearer",
    "authorization",
    "abcdefghij",
    "abcdefg",
    "12345678",
    "1234567890",
    "abcdefghijklmnopqrstuvwxyz",
    "abcdefghijklmnopqrstuvwxyz0123456789",
}

_FALSE_POSITIVE_VALUE_RE = re.compile(
    r"(?i)^(?:"
    r"\$\{?[\w.-]+\}?"  # env var refs
    r"|os\.environ(?:\.get)?"
    r"|settings\."
    r"|config\."
    r"|process\.env"
    r"|CharField\b"
    r"|TextField\b"
    r"|PasswordField\b"
    r"|serializers?\."
    r"|get_env\b"
    r"|getenv\b"
    r"|None\b"
    r"|True\b"
    r"|False\b"
    r"|<.*>"  # <your-secret>
    r"|your[_-].*"
    r"|xxx+"
    r"|asdf+"
    r"|lorem.*"
    r"|invalid-jwt"
    r"|test[_-]?token"
    r"|dummy[_-]?token"
    r")$"
)

_FALSE_POSITIVE_CONTEXT_RE = re.compile(
    r"(?i)(?:\bpassword\s*=\s*True\b"
    r"|\bpassword\s*=\s*False\b"
    r"|\bwrite_only\s*=\s*True\b"
    r"|\.get\(\s*['\"]PASSWORD['\"]"
    r"|\.get\(\s*['\"][^'\"]*SECRET[^'\"]*['\"]"
    r"|os\.environ"
    r"|CharField\s*\("
    r"|PasswordField\s*\("
    r"|serializers?\.CharField"
    r"|Bearer\s+(?:authentication|token|prefix|access)\b"
    r"|Authorization:\s*Bearer\s*$"
    r")"
)

_ENV_SECRET_KEY_RE = re.compile(
    r"(?i)(?:SECRET|PASSWORD|PASSWD|TOKEN|PRIVATE|CREDENTIAL|API[_-]?KEY|"
    r"ACCESS[_-]?KEY|CLIENT[_-]?SECRET|WEBHOOK|SIGNING|AUTH)"
)

_ENV_NON_SECRET_KEY_RE = re.compile(
    r"(?i)(?:_URL|_URI|_HOST|_ADDRESS|_PATH|_EMAIL|_ID$|BASE_PATH|"
    r"QUEUE_URL|WEB_APP|LMS_HOST|EXTERNAL_SYSTEM)"
)


def _extract_assigned_value(raw: str) -> str:
    """Best-effort value from `key = 'value'` / `key: "value"` style matches."""
    m = re.search(r"""[=:]\s*['"]([^'"]+)['"]""", raw)
    if m:
        return m.group(1).strip()
    m = re.search(r"""[=:]\s*([^\s'";,#]+)\s*$""", raw)
    if m:
        return m.group(1).strip()
    return raw.strip().strip("'\"")


def _is_false_positive(secret_type: str, raw: str, context: str = "") -> bool:
    value = _extract_assigned_value(raw)
    value_l = value.lower()

    if value_l in _FALSE_POSITIVE_VALUES:
        return True
    if _FALSE_POSITIVE_VALUE_RE.match(value):
        return True
    if context and _FALSE_POSITIVE_CONTEXT_RE.search(context):
        return True

    # Django / API serializer fields: password=True means write_only, not a secret
    if secret_type == "DATABASE_PASSWORD":
        if re.search(r"(?i)password\s*=\s*(?:True|False|None)\b", raw) or re.search(
            r"(?i)password\s*=\s*(?:True|False|None)\b", context
        ):
            return True
        if value_l in {"unused", "test", "password", "changeme", "postgres"}:
            return True
        if len(value) < 8:
            return True

    if secret_type in {"AZURE_CLIENT_SECRET", "AUTH0_CLIENT_SECRET", "SECRET_KEY_GENERIC"}:
        if value_l in {"secret", "client_secret", "client-secret"} or "Field" in value:
            return True
        if re.search(r"(?i)(?:SECRET|CLIENT_SECRET)\b\s*$", value):
            return True

    if secret_type == "BEARER_TOKEN":
        if re.search(
            r"(?i)Bearer\s+(?:authentication|token|prefix|access|tokens)\b",
            raw,
        ):
            return True
        if re.search(r"(?i)invalid-jwt|test-jwt|dummy", raw):
            return True

    if secret_type == "ACCESS_TOKEN_GENERIC":
        if value_l in {"access_token", "refresh_token", "token"}:
            return True
        if re.search(r"(?i)STORE|SESSION|COOKIE", value):
            return True

    if secret_type == "OKTA_TOKEN":
        # Migration dependency names: 0003_something with underscores
        if "_" in raw:
            return True

    if secret_type == "HIGH_ENTROPY_STRING":
        if re.fullmatch(r"[A-Za-z]+", value) and len(set(value.lower())) < 12:
            return True  # alphabet dumps
        if re.fullmatch(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", value_l):
            return False  # UUID may still be sensitive; keep
        if "template" in value_l or "version" in value_l or "storage" in value_l:
            return True

    return False


def _looks_like_secret(value: str) -> bool:
    if len(value) < ENTROPY_MIN_LEN:
        return False
    if value.startswith("$") or value.startswith("${"):
        return False
    if re.fullmatch(r"https?://\S+", value):
        return False
    if value.lower() in _FALSE_POSITIVE_VALUES:
        return False
    if _FALSE_POSITIVE_VALUE_RE.match(value):
        return False
    return _shannon_entropy(value) >= ENTROPY_THRESHOLD


def _env_key_looks_sensitive(key: str) -> bool:
    """Only treat .env keys as secrets when the name implies a credential."""
    key = key.strip()
    if key.lower().startswith("export "):
        key = key[7:].strip()
    if _ENV_NON_SECRET_KEY_RE.search(key) and not re.search(
        r"(?i)(?:SECRET|PASSWORD|TOKEN|PRIVATE|KEY)$", key
    ):
        # URLs/hosts/emails are not secrets unless the key ends in SECRET/TOKEN/KEY
        if not _ENV_SECRET_KEY_RE.search(key):
            return False
        # e.g. WEBHOOK_URL still sensitive; HOST_ADDRESS is not
        if re.search(r"(?i)(?:HOST|ADDRESS|EMAIL|PATH|BASE_PATH)$", key):
            return False
    return bool(_ENV_SECRET_KEY_RE.search(key))


def _unique_rglob(root: Path, pattern: str) -> List[Path]:
    seen: set[Path] = set()
    files: List[Path] = []
    for path in root.rglob(pattern):
        if not path.is_file():
            continue
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        files.append(path)
    return files


def _load_allowlist(root: Path) -> List[re.Pattern[str]]:
    patterns: List[re.Pattern[str]] = []
    for name in (".secretsignore", "secrets-allowlist.txt"):
        path = root / name
        if not path.is_file():
            continue
        try:
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    patterns.append(re.compile(line))
                except re.error:
                    patterns.append(re.compile(re.escape(line)))
        except OSError as exc:
            _warn(f"Could not read allowlist {path}: {exc}")
    return patterns


def _allowed(allowlist: List[re.Pattern[str]], raw: str, file_path: str, context: str) -> bool:
    haystacks = (raw, file_path, context)
    return any(p.search(h) for p in allowlist for h in haystacks if h)
