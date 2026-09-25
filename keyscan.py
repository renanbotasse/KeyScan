#!/usr/bin/env python3
"""
KeyScan — secrets & git history scanner
====================================================

Discover exposed credentials in code and git history, verify compromise
status (live provider checks), remediate/rotate when admin creds are set,
and prevent future leaks via pre-commit hooks and CI/CD.

Dependencies: None (Python 3.9+ stdlib only)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import math
import os
import re
import smtplib
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Pattern, Tuple

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class SecretPattern:
    name: str
    pattern: str
    severity: str = "HIGH"
    description: str = ""
    regex: Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        flags = re.IGNORECASE if "password" in self.name.lower() else 0
        self.regex = re.compile(self.pattern, flags)

    def match(self, text: str) -> Optional[re.Match[str]]:
        return self.regex.search(text)


@dataclass
class SecretFinding:
    secret_type: str
    severity: str
    file_path: str
    line_number: Optional[int] = None
    matched_text: str = ""  # redacted preview
    context: str = ""
    source: str = "current_code"
    commit_hash: Optional[str] = None
    commit_author: Optional[str] = None
    commit_date: Optional[str] = None
    raw_hash: str = ""  # sha256 of raw secret (safe to store)
    entropy: Optional[float] = None
    is_compromised: bool = False
    compromise_evidence: str = ""
    key_status: str = "unknown"  # active | revoked | invalid | format_valid | unknown | pwned
    damage_scope: str = ""
    remediation: str = ""
    rotation_result: str = ""


@dataclass
class TimelineEntry:
    secret_fingerprint: str
    secret_type: str
    matched_preview: str
    file_path: str
    first_commit: str
    first_author: str
    first_date: str
    last_commit: str
    last_author: str
    last_date: str
    commit_count: int


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

SECRET_PATTERNS: List[SecretPattern] = [
    # --- Cloud ---
    SecretPattern("AWS_ACCESS_KEY", r"AKIA[0-9A-Z]{16}", "CRITICAL", "AWS Access Key ID"),
    SecretPattern(
        "AWS_SECRET_KEY",
        r"aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "CRITICAL",
        "AWS Secret Access Key",
    ),
    SecretPattern(
        "AWS_SESSION_TOKEN",
        r"(?:aws)?_?session_token\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{100,})['\"]?",
        "CRITICAL",
        "AWS Session Token",
    ),
    SecretPattern(
        "AZURE_STORAGE_KEY",
        r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{40,}",
        "CRITICAL",
        "Azure Storage Connection String",
    ),
    SecretPattern(
        "AZURE_CLIENT_SECRET",
        r"(?:azure)?[_-]?client[_-]?secret\s*[=:]\s*['\"]?([A-Za-z0-9~._-]{16,})['\"]?",
        "CRITICAL",
        "Azure Client Secret",
    ),
    SecretPattern(
        "GCP_SERVICE_ACCOUNT",
        r'"type"\s*:\s*"service_account"',
        "CRITICAL",
        "GCP Service Account JSON marker",
    ),
    SecretPattern(
        "DIGITALOCEAN_TOKEN",
        r"dop_v1_[a-f0-9]{64}",
        "CRITICAL",
        "DigitalOcean Personal Access Token",
    ),
    SecretPattern(
        "HEROKU_API_KEY",
        r"(?:heroku)?[_-]?api[_-]?key\s*[=:]\s*['\"]?([0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})['\"]?",
        "CRITICAL",
        "Heroku API Key",
    ),
    # --- Payments ---
    SecretPattern("STRIPE_API_KEY", r"sk_(?:live|test)_[0-9a-zA-Z]{20,}", "CRITICAL", "Stripe Secret Key"),
    SecretPattern(
        "STRIPE_PUBLISHABLE_KEY", r"pk_(?:live|test)_[0-9a-zA-Z]{20,}", "HIGH", "Stripe Publishable Key"
    ),
    SecretPattern("STRIPE_WEBHOOK_SECRET", r"whsec_[0-9a-zA-Z]{24,}", "HIGH", "Stripe Webhook Secret"),
    SecretPattern("SQUARE_ACCESS_TOKEN", r"sq0atp-[0-9A-Za-z\-_]{22}", "CRITICAL", "Square Access Token"),
    SecretPattern(
        "PAYPAL_TOKEN",
        r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
        "CRITICAL",
        "PayPal Access Token",
    ),
    SecretPattern("SHOPIFY_TOKEN", r"shpat_[a-fA-F0-9]{32}", "CRITICAL", "Shopify Admin API Token"),
    # --- Source control / CI ---
    SecretPattern("GITHUB_TOKEN", r"gh[pousr]_[A-Za-z0-9_]{36,255}", "CRITICAL", "GitHub PAT"),
    SecretPattern("GITLAB_TOKEN", r"glpat-[A-Za-z0-9\-_]{20,}", "CRITICAL", "GitLab Personal Access Token"),
    SecretPattern("BITBUCKET_TOKEN", r"(?:ATBB|ATCTT)[A-Za-z0-9]{20,}", "CRITICAL", "Bitbucket / Atlassian token"),
    SecretPattern("NPM_TOKEN", r"npm_[A-Za-z0-9]{36}", "CRITICAL", "npm Access Token"),
    SecretPattern("PYPI_TOKEN", r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}", "CRITICAL", "PyPI API Token"),
    SecretPattern(
        "CIRCLECI_TOKEN",
        r"(?:circle[_-]?ci|CIRCLECI)[_-]?(?:token|TOKEN)\s*[=:]\s*['\"]?([a-f0-9]{40})['\"]?",
        "CRITICAL",
        "CircleCI API Token",
    ),
    SecretPattern(
        "TERRAFORM_CLOUD_TOKEN",
        r"(?:terraform[_-]?(?:cloud)?[_-]?token|TFE_TOKEN)\s*[=:]\s*['\"]?([A-Za-z0-9.\-]{20,})['\"]?",
        "CRITICAL",
        "Terraform Cloud Token",
    ),
    SecretPattern("HASHICORP_VAULT", r"hvs\.[A-Za-z0-9_-]{90,}", "CRITICAL", "Vault Token"),
    # --- AI / ML ---
    SecretPattern(
        "OPENAI_API_KEY",
        r"sk-proj-[A-Za-z0-9_-]{40,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}|sk-[A-Za-z0-9]{48}",
        "CRITICAL",
        "OpenAI API Key",
    ),
    SecretPattern("ANTHROPIC_API_KEY", r"sk-ant-[A-Za-z0-9\-_]{40,}", "CRITICAL", "Anthropic API Key"),
    SecretPattern("HUGGINGFACE_TOKEN", r"hf_[A-Za-z0-9]{34,}", "CRITICAL", "Hugging Face Token"),
    SecretPattern("REPLICATE_TOKEN", r"r8_[A-Za-z0-9]{37}", "HIGH", "Replicate API Token"),
    # --- Messaging ---
    SecretPattern("SLACK_BOT_TOKEN", r"xox[baprs]-[0-9A-Za-z-]{10,}", "HIGH", "Slack Token"),
    SecretPattern(
        "SLACK_WEBHOOK",
        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        "HIGH",
        "Slack Incoming Webhook",
    ),
    SecretPattern(
        "DISCORD_WEBHOOK",
        r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
        "HIGH",
        "Discord Webhook URL",
    ),
    SecretPattern("TELEGRAM_BOT_TOKEN", r"\d{8,10}:[A-Za-z0-9_-]{35}", "HIGH", "Telegram Bot Token"),
    # --- Email / SMS ---
    SecretPattern("SENDGRID_KEY", r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", "CRITICAL", "SendGrid API Key"),
    SecretPattern("MAILGUN_KEY", r"key-[0-9a-zA-Z]{32}", "HIGH", "Mailgun API Key"),
    SecretPattern("MAILCHIMP_KEY", r"[0-9a-f]{32}-us[0-9]{1,2}", "HIGH", "Mailchimp API Key"),
    SecretPattern(
        "TWILIO_AUTH_TOKEN",
        r"(?:twilio[_-]?)?auth[_-]?token\s*[=:]\s*['\"]?([a-f0-9]{32})['\"]?",
        "HIGH",
        "Twilio Auth Token",
    ),
    SecretPattern("TWILIO_SID", r"AC[a-f0-9]{32}", "HIGH", "Twilio Account SID"),
    # --- Observability / SaaS ---
    SecretPattern(
        "DATADOG_API_KEY",
        r"(?:datadog)?[_-]?api[_-]?key\s*[=:]\s*['\"]?([a-f0-9]{32})['\"]?",
        "HIGH",
        "Datadog API Key",
    ),
    SecretPattern(
        "SENTRY_DSN",
        r"https://[0-9a-f]{32}@[a-z0-9.-]+\.ingest\.[a-z]+\.sentry\.io/\d+",
        "HIGH",
        "Sentry DSN",
    ),
    SecretPattern("NEW_RELIC_KEY", r"NRAK-[A-Z0-9]{27}", "HIGH", "New Relic API Key"),
    SecretPattern(
        "CLOUDFLARE_TOKEN",
        r"(?:cloudflare)?[_-]?(?:api[_-]?)?token\s*[=:]\s*['\"]?([A-Za-z0-9_-]{40})['\"]?",
        "CRITICAL",
        "Cloudflare API Token",
    ),
    SecretPattern("NOTION_TOKEN", r"secret_[A-Za-z0-9]{43}", "HIGH", "Notion Integration Token"),
    SecretPattern("AIRTABLE_PAT", r"pat[A-Za-z0-9]{14}\.[0-9a-f]{16}", "HIGH", "Airtable PAT"),
    # --- Auth / platforms ---
    SecretPattern(
        "AUTH0_CLIENT_SECRET",
        r"(?:auth0)?[_-]?client[_-]?secret\s*[=:]\s*['\"]?([A-Za-z0-9_-]{32,})['\"]?",
        "CRITICAL",
        "Auth0 Client Secret",
    ),
    SecretPattern("OKTA_TOKEN", r"00[A-Za-z0-9_-]{40}", "HIGH", "Okta API Token"),
    SecretPattern(
        "VERCEL_TOKEN",
        r"(?:vercel)?[_-]?token\s*[=:]\s*['\"]?([A-Za-z0-9]{24})['\"]?",
        "HIGH",
        "Vercel Token",
    ),
    SecretPattern(
        "NETLIFY_TOKEN",
        r"(?:netlify)?[_-]?(?:auth[_-]?)?token\s*[=:]\s*['\"]?([A-Za-z0-9_-]{40,})['\"]?",
        "HIGH",
        "Netlify Access Token",
    ),
    # --- Tokens / generic ---
    SecretPattern(
        "JWT_TOKEN",
        r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+",
        "HIGH",
        "JWT Token",
    ),
    SecretPattern("BEARER_TOKEN", r"(?:Bearer|bearer)\s+[A-Za-z0-9\-._~+/]+=*", "HIGH", "Bearer Token"),
    SecretPattern(
        "BASIC_AUTH_HEADER",
        r"(?:Authorization|authorization)\s*[=:]\s*['\"]?Basic\s+[A-Za-z0-9+/=]{12,}['\"]?",
        "HIGH",
        "HTTP Basic Auth header",
    ),
    SecretPattern(
        "API_KEY_GENERIC",
        r"(?:api[_-]?key|apikey|api_secret)\s*[=:]\s*['\"]?([A-Za-z0-9_-]{32,})['\"]?",
        "HIGH",
        "Generic API Key",
    ),
    SecretPattern(
        "SECRET_KEY_GENERIC",
        r"(?:secret[_-]?key|app[_-]?secret|client[_-]?secret)\s*[=:]\s*['\"]?([A-Za-z0-9_/=+\-]{16,})['\"]?",
        "HIGH",
        "Generic secret / client secret",
    ),
    SecretPattern(
        "INTEGRATION_TOKEN",
        r"(?:integration|webhook)[_-](?:token|key|secret)\s*[=:]\s*['\"]?([A-Za-z0-9_-]{16,})['\"]?",
        "HIGH",
        "Generic integration token",
    ),
    SecretPattern(
        "ACCESS_TOKEN_GENERIC",
        r"(?:access[_-]?token|refresh[_-]?token)\s*[=:]\s*['\"]?([A-Za-z0-9._\-]{20,})['\"]?",
        "HIGH",
        "Generic access/refresh token",
    ),
    # --- Databases / brokers ---
    SecretPattern(
        "DATABASE_PASSWORD",
        r"(?:password|passwd|pwd)\s*[=:]\s*['\"]?([^'\"\s;#]{4,})['\"]?",
        "CRITICAL",
        "Database Password",
    ),
    SecretPattern(
        "MONGODB_URI",
        r"mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@[a-zA-Z0-9._-]+",
        "CRITICAL",
        "MongoDB URI with credentials",
    ),
    SecretPattern(
        "POSTGRES_URI",
        r"postgres(?:ql)?://[^:\s]+:[^@\s]+@[a-zA-Z0-9._-]+",
        "CRITICAL",
        "PostgreSQL URI with credentials",
    ),
    SecretPattern(
        "MYSQL_URI", r"mysql://[^:\s]+:[^@\s]+@[a-zA-Z0-9._-]+", "CRITICAL", "MySQL URI with credentials"
    ),
    SecretPattern(
        "REDIS_URI",
        r"rediss?://[^:\s]*:[^@\s]+@[a-zA-Z0-9._-]+",
        "CRITICAL",
        "Redis URI with credentials",
    ),
    SecretPattern(
        "AMQP_URI",
        r"amqps?://[^:\s]+:[^@\s]+@[a-zA-Z0-9._-]+",
        "CRITICAL",
        "AMQP / RabbitMQ URI with credentials",
    ),
    SecretPattern(
        "PIP_URL_CREDENTIALS",
        r"(?:git\+)?https?://[^:\s/]+:[^@\s/]+@(?:github\.com|gitlab\.com|bitbucket\.org|pypi\.[^\s/]+|[^\s/]*artifacts?[^\s/]*)[^\s]*",
        "HIGH",
        "URL with embedded credentials",
    ),
    # --- Google / Firebase ---
    SecretPattern("FIREBASE_KEY", r"AIza[0-9A-Za-z\-_]{35}", "HIGH", "Firebase / Google API Key"),
    SecretPattern("GOOGLE_OAUTH", r"ya29\.[0-9A-Za-z\-_]+", "HIGH", "Google OAuth Access Token"),
    # --- Crypto / keys ---
    SecretPattern(
        "PRIVATE_KEY_PEM",
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----",
        "CRITICAL",
        "Private Key (PEM/OpenSSH)",
    ),
    SecretPattern("PGP_PRIVATE_KEY", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "CRITICAL", "PGP Private Key"),
    SecretPattern("PUTTY_PRIVATE_KEY", r"PuTTY-User-Key-File-[0-9.]+", "CRITICAL", "PuTTY Private Key"),
    SecretPattern("AGE_SECRET_KEY", r"AGE-SECRET-KEY-1[A-Z0-9]{58}", "CRITICAL", "age encryption secret key"),
]

SKIP_DIRS = {
    "node_modules",
    ".git",
    "venv",
    ".venv",
    "__pycache__",
    ".tox",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
    "secrets-report",
}
SKIP_FILES = {
    "keyscan.py",
    "KeyScan_Documentation.md",
    "README.md",
}
SCAN_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".env",
    ".yaml",
    ".yml",
    ".json",
    ".txt",
    ".sh",
    ".bash",
    ".zsh",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".xml",
    ".properties",
    ".md",
    ".tf",
    ".hcl",
}
EXTRA_SCAN_NAMES = {"Pipfile", "Dockerfile", "docker-compose.yml", "docker-compose.yaml"}
PIP_URL_RE = re.compile(r"(?:git\+)?https?://([^:\s/]+):([^@\s/]+)@([^\s#]+)", re.IGNORECASE)
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
ENTROPY_MIN_LEN = 20
ENTROPY_THRESHOLD = 4.5

DAMAGE_SCOPE = {
    "AWS_ACCESS_KEY": "Full AWS account access depending on IAM policy.",
    "AWS_SECRET_KEY": "Pairs with access key — AWS API signing capability.",
    "AZURE_STORAGE_KEY": "Full Azure Storage account access.",
    "STRIPE_API_KEY": "Create charges, refunds, access payment data.",
    "GITHUB_TOKEN": "Repo read/write, Actions, possibly org admin.",
    "GITLAB_TOKEN": "GitLab project/group access depending on scopes.",
    "OPENAI_API_KEY": "Billable AI API usage and data sent to the provider.",
    "ANTHROPIC_API_KEY": "Billable AI API usage and data sent to the provider.",
    "DATABASE_PASSWORD": "Direct database read/write; data exfiltration risk.",
    "MONGODB_URI": "Full MongoDB access for the embedded user.",
    "POSTGRES_URI": "Full PostgreSQL access for the embedded user.",
    "MYSQL_URI": "Full MySQL access for the embedded user.",
    "REDIS_URI": "Full Redis access for the embedded user.",
    "PRIVATE_KEY_PEM": "Impersonation, decrypt traffic, SSH/CI deploy access.",
    "SLACK_BOT_TOKEN": "Read/post messages per bot scopes.",
    "JWT_TOKEN": "API impersonation until expiry.",
    "FIREBASE_KEY": "Client API abuse; misconfig may expose data.",
    "SENDGRID_KEY": "Send email as your domain; phishing risk.",
    "NPM_TOKEN": "Publish/pull private npm packages.",
    "HIGH_ENTROPY_STRING": "Unknown secret-like material — treat as credential.",
}



# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


def _looks_like_secret(value: str) -> bool:
    if len(value) < ENTROPY_MIN_LEN:
        return False
    if value.startswith("$") or value.startswith("${"):
        return False
    # skip obvious non-secrets
    if re.fullmatch(r"[0-9a-f]{40}", value) and value.islower():
        # could be git sha — medium confidence; still flag via entropy only if mixed
        pass
    if re.fullmatch(r"https?://\S+", value):
        return False
    return _shannon_entropy(value) >= ENTROPY_THRESHOLD


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


# ---------------------------------------------------------------------------
# Secure vault (raw values for verification — never printed in reports)
# ---------------------------------------------------------------------------


class SecretVault:
    """Stores raw secrets keyed by sha256 hash. File mode 0600."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._data: Dict[str, Dict[str, str]] = {}
        if path.exists():
            try:
                self._data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                _warn(f"Could not load vault {path}: {exc}")
                self._data = {}

    def put(self, raw: str, secret_type: str, file_path: str) -> str:
        h = _sha256(raw)
        self._data[h] = {
            "raw": raw,
            "secret_type": secret_type,
            "file_path": file_path,
            "stored_at": _now_iso(),
        }
        return h

    def get(self, raw_hash: str) -> Optional[str]:
        item = self._data.get(raw_hash)
        return item.get("raw") if item else None

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class SecretScanner:
    def __init__(self, project_root: str = ".", store_raw: bool = False, vault_path: Optional[Path] = None) -> None:
        self.project_root = Path(project_root).resolve()
        self.patterns = list(SECRET_PATTERNS)
        self.allowlist = _load_allowlist(self.project_root)
        self.store_raw = store_raw
        self.vault = SecretVault(vault_path or (self.project_root / "secrets-report" / ".secrets-vault.json"))
        self._aws_pairs: Dict[str, Dict[str, str]] = defaultdict(dict)  # file -> {access, secret}

    def _should_skip(self, path: Path) -> bool:
        if any(part in SKIP_DIRS for part in path.parts):
            return True
        if path.name in SKIP_FILES:
            return True
        if path.suffix in {".yml", ".yaml"} and "workflows" in path.parts and path.name.startswith("secrets-scan"):
            return True
        if path.name == ".secrets-vault.json":
            return True
        return False

    def _rel(self, path: Path) -> str:
        return str(path.relative_to(self.project_root))

    def _make_finding(
        self,
        secret_type: str,
        severity: str,
        file_path: str,
        line_num: Optional[int],
        raw: str,
        context: str,
        source: str,
        commit_hash: Optional[str] = None,
        commit_author: Optional[str] = None,
        commit_date: Optional[str] = None,
    ) -> Optional[SecretFinding]:
        if _allowed(self.allowlist, raw, file_path, context):
            return None
        raw_hash = _sha256(raw)
        if self.store_raw:
            self.vault.put(raw, secret_type, file_path)
        # Track AWS pairs for STS validation
        if secret_type == "AWS_ACCESS_KEY":
            self._aws_pairs[file_path]["access"] = raw
            self._aws_pairs[file_path]["access_hash"] = raw_hash
        elif secret_type == "AWS_SECRET_KEY":
            # capture group value if present in raw assignment
            m = re.search(r"([A-Za-z0-9/+=]{40})", raw)
            secret_val = m.group(1) if m else raw
            self._aws_pairs[file_path]["secret"] = secret_val
            self._aws_pairs[file_path]["secret_hash"] = _sha256(secret_val)
            if self.store_raw:
                self.vault.put(secret_val, secret_type, file_path)
        return SecretFinding(
            secret_type=secret_type,
            severity=severity,
            file_path=file_path,
            line_number=line_num,
            matched_text=_redact(raw),
            context=context.strip()[:120],
            source=source,
            commit_hash=commit_hash,
            commit_author=commit_author,
            commit_date=commit_date,
            raw_hash=raw_hash,
            entropy=round(_shannon_entropy(raw), 3),
            damage_scope=DAMAGE_SCOPE.get(secret_type, ""),
        )

    def _match_line(
        self,
        line: str,
        file_path: str,
        line_num: Optional[int],
        source: str,
        commit_hash: Optional[str] = None,
        commit_author: Optional[str] = None,
        commit_date: Optional[str] = None,
        entropy_scan: bool = False,
    ) -> List[SecretFinding]:
        found: List[SecretFinding] = []
        matched_spans: List[Tuple[int, int]] = []
        for pattern in self.patterns:
            for match in pattern.regex.finditer(line):
                raw = match.group(0)
                finding = self._make_finding(
                    pattern.name,
                    pattern.severity,
                    file_path,
                    line_num,
                    raw,
                    line,
                    source,
                    commit_hash,
                    commit_author,
                    commit_date,
                )
                if finding:
                    found.append(finding)
                    matched_spans.append(match.span())

        if entropy_scan:
            for token in re.findall(r"['\"]([A-Za-z0-9_\-+/=]{20,})['\"]|(?<![A-Za-z0-9])([A-Za-z0-9_\-+/=]{32,})", line):
                raw = token[0] or token[1]
                if not raw or not _looks_like_secret(raw):
                    continue
                # skip if already covered by a pattern match
                pos = line.find(raw)
                if pos >= 0 and any(s <= pos < e for s, e in matched_spans):
                    continue
                finding = self._make_finding(
                    "HIGH_ENTROPY_STRING",
                    "MEDIUM",
                    file_path,
                    line_num,
                    raw,
                    line,
                    source,
                    commit_hash,
                    commit_author,
                    commit_date,
                )
                if finding:
                    found.append(finding)
        return found

    def scan_current_code(self, extensions: Optional[List[str]] = None, entropy: bool = True) -> List[SecretFinding]:
        exts = set(extensions) if extensions else SCAN_EXTENSIONS
        findings: List[SecretFinding] = []
        for file_path in self.project_root.rglob("*"):
            if not file_path.is_file() or self._should_skip(file_path):
                continue
            name = file_path.name
            if name.startswith(".env"):
                continue
            if name.startswith("requirements") and name.endswith(".txt"):
                continue
            if file_path.suffix not in exts and name not in EXTRA_SCAN_NAMES:
                continue
            if _is_binary(file_path):
                continue
            try:
                rel = self._rel(file_path)
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_num, line in enumerate(f, 1):
                        findings.extend(
                            self._match_line(line, rel, line_num, "current_code", entropy_scan=entropy)
                        )
            except OSError as exc:
                _warn(f"Could not scan {file_path}: {exc}")
        return findings

    def scan_env_file(self) -> List[SecretFinding]:
        findings: List[SecretFinding] = []
        for env_file in _unique_rglob(self.project_root, ".env*"):
            if self._should_skip(env_file):
                continue
            try:
                rel = self._rel(env_file)
                with open(env_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line_num, line in enumerate(f, 1):
                        stripped = line.strip()
                        if not stripped or stripped.startswith("#") or "=" not in stripped:
                            continue
                        key, value = stripped.split("=", 1)
                        key, value = key.strip(), value.strip().strip("'\"")
                        if len(value) <= 20 or value.startswith("$") or value.startswith("${"):
                            continue
                        secret_type, severity = "ENV_SECRET_VALUE", "HIGH"
                        for pattern in self.patterns:
                            if pattern.match(value) or pattern.match(line):
                                secret_type, severity = pattern.name, pattern.severity
                                break
                        finding = self._make_finding(
                            secret_type, severity, rel, line_num, value, f"{key}=***", ".env"
                        )
                        if finding:
                            finding.matched_text = key  # report key name, not value
                            findings.append(finding)
            except OSError as exc:
                _warn(f"Could not scan {env_file}: {exc}")
        return findings

    def scan_requirements(self) -> List[SecretFinding]:
        findings: List[SecretFinding] = []
        for req_file in _unique_rglob(self.project_root, "requirements*.txt"):
            if self._should_skip(req_file):
                continue
            try:
                rel = self._rel(req_file)
                with open(req_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line_num, line in enumerate(f, 1):
                        match = PIP_URL_RE.search(line)
                        if not match:
                            continue
                        user, pwd, host = match.groups()
                        raw = match.group(0)
                        finding = self._make_finding(
                            "PIP_URL_CREDENTIALS",
                            "HIGH",
                            rel,
                            line_num,
                            raw,
                            line,
                            "requirements",
                        )
                        if finding:
                            finding.matched_text = f"{user}:***@{host}"
                            if self.store_raw:
                                self.vault.put(pwd, "PIP_URL_PASSWORD", rel)
                            findings.append(finding)
            except OSError as exc:
                _warn(f"Could not scan {req_file}: {exc}")
        return findings

    def scan_dockerfile(self) -> List[SecretFinding]:
        """Scan Dockerfile / compose for ENV secrets and COPY of .env."""
        findings: List[SecretFinding] = []
        names = ("Dockerfile", "Dockerfile.*", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")
        files: List[Path] = []
        for name in names:
            if "*" in name:
                files.extend(_unique_rglob(self.project_root, name))
            else:
                files.extend(_unique_rglob(self.project_root, name))
        seen: set[Path] = set()
        for path in files:
            resolved = path.resolve()
            if resolved in seen or self._should_skip(path):
                continue
            seen.add(resolved)
            try:
                rel = self._rel(path)
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_num, line in enumerate(f, 1):
                        findings.extend(self._match_line(line, rel, line_num, "dockerfile", entropy_scan=True))
                        if re.search(r"\b(?:ENV|ARG)\b.+(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE)", line, re.I):
                            # already covered by patterns; also catch bare ENV SECRET=value
                            m = re.search(r"(?:ENV|ARG)\s+\w+=(.*)$", line)
                            if m and _looks_like_secret(m.group(1).strip().strip("'\"")):
                                raw = m.group(1).strip().strip("'\"")
                                finding = self._make_finding(
                                    "DOCKER_ENV_SECRET", "HIGH", rel, line_num, raw, line, "dockerfile"
                                )
                                if finding:
                                    findings.append(finding)
            except OSError as exc:
                _warn(f"Could not scan {path}: {exc}")
        return findings

    def scan_git_history(self, commit_limit: int = 500, skip_merges: bool = True, entropy: bool = False) -> List[SecretFinding]:
        findings: List[SecretFinding] = []
        if not (self.project_root / ".git").exists():
            _warn("Not a git repository")
            return findings
        try:
            log_cmd = ["git", "log", f"--max-count={commit_limit}", "--format=%H%x09%an%x09%aI"]
            if skip_merges:
                log_cmd.append("--no-merges")
            result = subprocess.run(log_cmd, cwd=self.project_root, capture_output=True, text=True, timeout=120)
            if result.returncode != 0:
                _warn(f"git log failed: {result.stderr.strip()}")
                return findings

            commits: List[Tuple[str, str, str]] = []
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                parts = line.split("\t", 2)
                if len(parts) == 3:
                    commits.append((parts[0], parts[1], parts[2]))

            for commit_hash, author, date in commits:
                try:
                    diff_result = subprocess.run(
                        ["git", "show", "--pretty=format:", "--unified=0", commit_hash],
                        cwd=self.project_root,
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    if diff_result.returncode != 0:
                        continue
                    current_file = commit_hash[:7]
                    for line in diff_result.stdout.splitlines():
                        if line.startswith("diff --git"):
                            m = re.search(r" b/(.+)$", line)
                            if m:
                                current_file = m.group(1)
                            continue
                        if line.startswith("+++ b/"):
                            current_file = line[6:]
                            continue
                        if not line.startswith("+") or line.startswith("+++"):
                            continue
                        findings.extend(
                            self._match_line(
                                line[1:],
                                file_path=current_file,
                                line_num=None,
                                source="git_history",
                                commit_hash=commit_hash,
                                commit_author=author,
                                commit_date=date,
                                entropy_scan=entropy,
                            )
                        )
                except subprocess.TimeoutExpired:
                    _warn(f"Timeout scanning commit {commit_hash[:7]}")
                except Exception as exc:  # noqa: BLE001
                    _warn(f"Could not scan commit {commit_hash[:7]}: {exc}")
        except FileNotFoundError:
            _warn("Git not found")
        except Exception as exc:  # noqa: BLE001
            _warn(f"Could not scan git history: {exc}")
        return findings

    def build_timeline(self, history_findings: List[SecretFinding]) -> List[TimelineEntry]:
        groups: Dict[str, List[SecretFinding]] = defaultdict(list)
        for finding in history_findings:
            if finding.source != "git_history" or not finding.commit_hash:
                continue
            key = f"{finding.secret_type}:{finding.raw_hash or finding.matched_text}:{finding.file_path}"
            groups[key].append(finding)
        timeline: List[TimelineEntry] = []
        for key, items in groups.items():
            ordered = sorted(items, key=lambda f: f.commit_date or "")
            first, last = ordered[0], ordered[-1]
            unique_commits = {f.commit_hash for f in ordered if f.commit_hash}
            timeline.append(
                TimelineEntry(
                    secret_fingerprint=_fingerprint(key),
                    secret_type=first.secret_type,
                    matched_preview=first.matched_text,
                    file_path=first.file_path,
                    first_commit=(first.commit_hash or "")[:12],
                    first_author=first.commit_author or "unknown",
                    first_date=first.commit_date or "",
                    last_commit=(last.commit_hash or "")[:12],
                    last_author=last.commit_author or "unknown",
                    last_date=last.commit_date or "",
                    commit_count=len(unique_commits),
                )
            )
        return sorted(timeline, key=lambda t: t.first_date)

    def aws_credential_pairs(self) -> List[Dict[str, str]]:
        pairs = []
        for file_path, data in self._aws_pairs.items():
            if data.get("access") and data.get("secret"):
                pairs.append({"file_path": file_path, **data})
        return pairs


# ---------------------------------------------------------------------------
# History cleanup
# ---------------------------------------------------------------------------


class HistoryCleanup:
    @staticmethod
    def generate_removal_plan(findings: List[SecretFinding], vault: Optional[SecretVault] = None) -> Dict[str, Any]:
        # Prefer exact raw values from vault for BFG replace-text file
        exact: List[str] = []
        if vault:
            for f in findings:
                if f.source == "git_history" and f.raw_hash:
                    raw = vault.get(f.raw_hash)
                    if raw:
                        exact.append(raw)
        paths = sorted({f.file_path for f in findings if f.source == "git_history" and f.file_path})
        return {
            "warning": (
                "Rewriting history requires force-push and credential rotation. "
                "Coordinate with the team before proceeding."
            ),
            "checklist": [
                "1. Rotate/revoke every exposed credential first",
                "2. Backup the repository (git clone --mirror)",
                "3. Write exact secret strings to secrets-to-remove.txt (one per line)",
                "4. Run BFG or git filter-repo locally",
                "5. Force-push all branches/tags after team agreement",
                "6. Ask all developers to re-clone",
                "7. Verify with a fresh scan-history run",
            ],
            "secrets_count": len(exact) or len([f for f in findings if f.source == "git_history"]),
            "affected_paths": paths[:50],
            "passwords_file": "secrets-to-remove.txt",
            "bfg_commands": [
                "# Write secrets (one per line) to secrets-to-remove.txt",
                "java -jar bfg.jar --replace-text secrets-to-remove.txt",
                "git reflog expire --expire=now --all",
                "git gc --prune=now --aggressive",
            ],
            "filter_repo_commands": [
                "# Preferred over filter-branch:",
                *[f"git filter-repo --path {p} --invert-paths" for p in paths[:10]],
                "git filter-repo --replace-text secrets-to-remove.txt",
            ],
            "filter_branch_fallback": [
                "git filter-branch --force --index-filter \\",
                '  "git rm --cached --ignore-unmatch PATH_WITH_SECRET" \\',
                "  --prune-empty --tag-name-filter cat -- --all",
            ],
            "exact_secrets_available": bool(exact),
            "deployment_note": (
                "After cleanup, redeploy with rotated secrets. Update CI/CD, containers, and secret managers."
            ),
        }

    @staticmethod
    def write_secrets_file(path: Path, findings: List[SecretFinding], vault: SecretVault) -> int:
        lines: List[str] = []
        for f in findings:
            if not f.raw_hash:
                continue
            raw = vault.get(f.raw_hash)
            if raw and raw not in lines:
                lines.append(raw)
        path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return len(lines)


# ---------------------------------------------------------------------------
# AWS SigV4 (stdlib)
# ---------------------------------------------------------------------------


class AWSSigner:
    """Minimal AWS Signature Version 4 for STS GetCallerIdentity / Secrets Manager."""

    @staticmethod
    def _sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    @classmethod
    def _signature_key(cls, secret_key: str, datestamp: str, region: str, service: str) -> bytes:
        k_date = cls._sign(("AWS4" + secret_key).encode("utf-8"), datestamp)
        k_region = cls._sign(k_date, region)
        k_service = cls._sign(k_region, service)
        return cls._sign(k_service, "aws4_request")

    @classmethod
    def request(
        cls,
        access_key: str,
        secret_key: str,
        method: str,
        url: str,
        region: str,
        service: str,
        payload: str = "",
        extra_headers: Optional[Dict[str, str]] = None,
        timeout: int = 10,
    ) -> Tuple[int, str]:
        parsed = urllib.parse.urlparse(url)
        host = parsed.netloc
        canonical_uri = parsed.path or "/"
        now = datetime.now(timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        datestamp = now.strftime("%Y%m%d")
        payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        headers = {
            "host": host,
            "x-amz-date": amz_date,
            "x-amz-content-sha256": payload_hash,
        }
        if extra_headers:
            headers.update({k.lower(): v for k, v in extra_headers.items()})

        signed_headers = ";".join(sorted(headers.keys()))
        canonical_headers = "".join(f"{k}:{headers[k]}\n" for k in sorted(headers.keys()))
        canonical_querystring = parsed.query
        canonical_request = "\n".join(
            [
                method,
                canonical_uri,
                canonical_querystring,
                canonical_headers,
                signed_headers,
                payload_hash,
            ]
        )
        credential_scope = f"{datestamp}/{region}/{service}/aws4_request"
        string_to_sign = "\n".join(
            [
                "AWS4-HMAC-SHA256",
                amz_date,
                credential_scope,
                hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
            ]
        )
        signing_key = cls._signature_key(secret_key, datestamp, region, service)
        signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        authorization = (
            f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        req_headers = {k: v for k, v in headers.items() if k != "host"}
        req_headers["Authorization"] = authorization
        req_headers["Content-Type"] = extra_headers.get("Content-Type", "application/x-www-form-urlencoded") if extra_headers else "application/x-www-form-urlencoded"

        data = payload.encode("utf-8") if payload else None
        req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            return exc.code, body
        except Exception as exc:  # noqa: BLE001
            return 0, str(exc)


# ---------------------------------------------------------------------------
# Compromise verification
# ---------------------------------------------------------------------------


class CompromiseVerifier:
    @staticmethod
    def check_haveibeenpwned_email(email: str, api_key: Optional[str] = None, timeout: int = 5) -> Dict[str, Any]:
        result: Dict[str, Any] = {"checked": False, "breached": False, "detail": ""}
        try:
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}"
            req = urllib.request.Request(url, headers={"User-Agent": "KeyScan/2.0"})
            if api_key:
                req.add_header("hibp-api-key", api_key)
            with urllib.request.urlopen(req, timeout=timeout) as response:
                result.update(checked=True, breached=True, detail="Email found in breach database")
                return result
        except urllib.error.HTTPError as exc:
            result["checked"] = True
            if exc.code == 404:
                result["detail"] = "Email not found in known breaches"
            elif exc.code == 401:
                result["detail"] = "HIBP API key required (set HIBP_API_KEY)"
            else:
                result["detail"] = f"HIBP HTTP {exc.code}"
            return result
        except Exception as exc:  # noqa: BLE001
            result["detail"] = f"HIBP check failed: {exc}"
            return result

    @staticmethod
    def check_pwned_password(password: str, timeout: int = 5) -> Dict[str, Any]:
        """HIBP Pwned Passwords k-anonymity API (no API key)."""
        result: Dict[str, Any] = {"checked": False, "pwned": False, "count": 0, "detail": ""}
        if _is_redacted(password) or len(password) < 4:
            result["detail"] = "Value unsuitable for Pwned Passwords check"
            return result
        try:
            digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
            prefix, suffix = digest[:5], digest[5:]
            req = urllib.request.Request(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"User-Agent": "KeyScan/2.0", "Add-Padding": "true"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
            for line in body.splitlines():
                parts = line.split(":")
                if len(parts) == 2 and parts[0].strip().upper() == suffix:
                    count = int(parts[1].strip())
                    result.update(
                        checked=True,
                        pwned=True,
                        count=count,
                        detail=f"Password appears in breaches ({count} times)",
                    )
                    return result
            result.update(checked=True, pwned=False, detail="Password not found in Pwned Passwords")
            return result
        except Exception as exc:  # noqa: BLE001
            result["detail"] = f"Pwned Passwords check failed: {exc}"
            return result

    @staticmethod
    def check_github_token_active(token: str, timeout: int = 5) -> Dict[str, Any]:
        result: Dict[str, Any] = {"checked": False, "status": "unknown", "detail": "", "scopes": ""}
        if _is_redacted(token) or not token.startswith("gh"):
            result["detail"] = "Not a usable GitHub token value"
            return result
        try:
            req = urllib.request.Request(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"Bearer {token}",
                    "User-Agent": "KeyScan/2.0",
                    "Accept": "application/vnd.github+json",
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as response:
                data = json.loads(response.read().decode())
                scopes = response.headers.get("X-OAuth-Scopes", "")
                login = data.get("login", "?")
                result.update(
                    checked=True,
                    status="active",
                    detail=f"Active as GitHub user '{login}'",
                    scopes=scopes,
                )
                return result
        except urllib.error.HTTPError as exc:
            result.update(
                checked=True,
                status="revoked" if exc.code in (401, 403) else "invalid",
                detail=f"GitHub HTTP {exc.code}",
            )
            return result
        except Exception as exc:  # noqa: BLE001
            result["detail"] = f"GitHub check failed: {exc}"
            return result

    @staticmethod
    def check_stripe_key_active(api_key: str, timeout: int = 5) -> Dict[str, Any]:
        result: Dict[str, Any] = {"checked": False, "status": "unknown", "detail": ""}
        if _is_redacted(api_key) or not api_key.startswith("sk_"):
            result["detail"] = "Not a usable Stripe secret key value"
            return result
        try:
            req = urllib.request.Request("https://api.stripe.com/v1/balance")
            creds = base64.b64encode(f"{api_key}:".encode()).decode()
            req.add_header("Authorization", f"Basic {creds}")
            with urllib.request.urlopen(req, timeout=timeout) as response:
                result.update(checked=True, status="active", detail="Stripe API accepted the key")
                return result
        except urllib.error.HTTPError as exc:
            result.update(
                checked=True,
                status="revoked" if exc.code in (401, 403) else "invalid",
                detail=f"Stripe HTTP {exc.code}",
            )
            return result
        except Exception as exc:  # noqa: BLE001
            result["detail"] = f"Stripe check failed: {exc}"
            return result

    @staticmethod
    def check_slack_token_active(token: str, timeout: int = 5) -> Dict[str, Any]:
        result: Dict[str, Any] = {"checked": False, "status": "unknown", "detail": ""}
        if _is_redacted(token) or not token.startswith("xox"):
            result["detail"] = "Not a usable Slack token"
            return result
        try:
            req = urllib.request.Request(
                "https://slack.com/api/auth.test",
                data=b"",
                headers={"Authorization": f"Bearer {token}"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as response:
                data = json.loads(response.read().decode())
                if data.get("ok"):
                    result.update(
                        checked=True,
                        status="active",
                        detail=f"Slack OK team={data.get('team')} user={data.get('user')}",
                    )
                else:
                    result.update(checked=True, status="invalid", detail=data.get("error", "slack error"))
                return result
        except Exception as exc:  # noqa: BLE001
            result["detail"] = f"Slack check failed: {exc}"
            return result

    @staticmethod
    def check_aws_sts(access_key: str, secret_key: str, region: str = "us-east-1", timeout: int = 10) -> Dict[str, Any]:
        result: Dict[str, Any] = {"checked": False, "status": "unknown", "detail": "", "arn": ""}
        if _is_redacted(access_key) or _is_redacted(secret_key):
            result["detail"] = "Redacted AWS credentials; enable --store-raw to verify"
            return result
        if not re.fullmatch(r"AKIA[0-9A-Z]{16}", access_key):
            result.update(checked=True, status="invalid", detail="Access key format invalid")
            return result
        payload = "Action=GetCallerIdentity&Version=2011-06-15"
        status, body = AWSSigner.request(
            access_key,
            secret_key,
            "POST",
            "https://sts.amazonaws.com/",
            region,
            "sts",
            payload=payload,
            extra_headers={"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
            timeout=timeout,
        )
        result["checked"] = True
        if status == 200 and "Arn" in body:
            arn_m = re.search(r"<Arn>([^<]+)</Arn>", body)
            arn = arn_m.group(1) if arn_m else ""
            result.update(status="active", detail="STS GetCallerIdentity succeeded", arn=arn)
        elif status in (403, 401):
            result.update(status="revoked", detail=f"STS denied HTTP {status}")
        elif status == 0:
            result.update(status="unknown", detail=f"STS network error: {body[:200]}")
        else:
            # InvalidClientTokenId etc.
            if "InvalidClientTokenId" in body or "SignatureDoesNotMatch" in body:
                result.update(status="invalid", detail=f"STS rejected credentials HTTP {status}")
            else:
                result.update(status="unknown", detail=f"STS HTTP {status}: {body[:200]}")
        return result

    @staticmethod
    def check_shodan(query: str, api_key: Optional[str] = None, timeout: int = 5) -> Dict[str, Any]:
        result: Dict[str, Any] = {"checked": False, "found": False, "detail": ""}
        if not api_key:
            result["detail"] = "Set SHODAN_API_KEY to enable Shodan checks"
            return result
        try:
            url = "https://api.shodan.io/shodan/host/search?" + urllib.parse.urlencode(
                {"key": api_key, "query": query}
            )
            with urllib.request.urlopen(url, timeout=timeout) as response:
                data = json.loads(response.read().decode())
                total = data.get("total", 0)
                result.update(checked=True, found=total > 0, detail=f"Shodan matches: {total}")
                return result
        except Exception as exc:  # noqa: BLE001
            result["detail"] = f"Shodan check failed: {exc}"
            return result

    @staticmethod
    def check_google_safe_browsing(url: str, api_key: Optional[str] = None, timeout: int = 5) -> Dict[str, Any]:
        result: Dict[str, Any] = {"checked": False, "unsafe": False, "detail": ""}
        if not api_key:
            result["detail"] = "Set GSB_API_KEY to enable Google Safe Browsing checks"
            return result
        try:
            endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find?" + urllib.parse.urlencode(
                {"key": api_key}
            )
            body = json.dumps(
                {
                    "client": {"clientId": "secrets-scanner", "clientVersion": "2.0"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}],
                    },
                }
            ).encode()
            req = urllib.request.Request(endpoint, data=body, method="POST")
            req.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(req, timeout=timeout) as response:
                data = json.loads(response.read().decode() or "{}")
                unsafe = bool(data.get("matches"))
                result.update(checked=True, unsafe=unsafe, detail="Listed" if unsafe else "Not listed")
                return result
        except Exception as exc:  # noqa: BLE001
            result["detail"] = f"GSB check failed: {exc}"
            return result

    @classmethod
    def verify_finding(
        cls,
        finding: SecretFinding,
        raw_value: str = "",
        aws_secret: str = "",
    ) -> SecretFinding:
        value = raw_value or ""
        status, evidence = "unknown", ""

        if finding.secret_type == "GITHUB_TOKEN" and value:
            r = cls.check_github_token_active(value)
            status, evidence = r.get("status", "unknown"), r.get("detail", "")
            if r.get("scopes"):
                evidence += f" scopes={r['scopes']}"
        elif finding.secret_type == "STRIPE_API_KEY" and value:
            r = cls.check_stripe_key_active(value)
            status, evidence = r.get("status", "unknown"), r.get("detail", "")
        elif finding.secret_type == "SLACK_BOT_TOKEN" and value:
            r = cls.check_slack_token_active(value)
            status, evidence = r.get("status", "unknown"), r.get("detail", "")
        elif finding.secret_type == "AWS_ACCESS_KEY":
            if value and aws_secret:
                r = cls.check_aws_sts(value, aws_secret)
                status, evidence = r.get("status", "unknown"), r.get("detail", "")
                if r.get("arn"):
                    evidence += f" arn={r['arn']}"
            elif value and re.fullmatch(r"AKIA[0-9A-Z]{16}", value):
                status, evidence = "format_valid", "Format OK; provide paired secret (vault) for STS check"
            else:
                evidence = "Enable --store-raw on scan for live AWS STS verification"
        elif finding.secret_type in {
            "DATABASE_PASSWORD",
            "ENV_SECRET_VALUE",
            "AWS_SECRET_KEY",
            "API_KEY_GENERIC",
            "HIGH_ENTROPY_STRING",
        } and value:
            r = cls.check_pwned_password(value)
            if r.get("pwned"):
                status, evidence = "pwned", r.get("detail", "")
            elif r.get("checked"):
                status, evidence = "not_pwned", r.get("detail", "")
            else:
                evidence = r.get("detail", "")
        else:
            evidence = "No automated live check for this type (or raw value unavailable); rotate as precaution"

        finding.key_status = status
        finding.is_compromised = status in {"active", "pwned"}
        finding.compromise_evidence = evidence
        finding.damage_scope = finding.damage_scope or DAMAGE_SCOPE.get(finding.secret_type, "")
        finding.remediation = RemediationPlanner.plan_for(finding)
        return finding

    @classmethod
    def verify_all(
        cls,
        findings: List[SecretFinding],
        vault: Optional[SecretVault] = None,
        aws_pairs: Optional[List[Dict[str, str]]] = None,
    ) -> Tuple[List[SecretFinding], Dict[str, Any]]:
        pair_by_access_hash = {}
        pair_by_file = {}
        for pair in aws_pairs or []:
            if pair.get("access_hash"):
                pair_by_access_hash[pair["access_hash"]] = pair
            pair_by_file[pair.get("file_path", "")] = pair

        external: Dict[str, Any] = {"emails": [], "shodan": None, "gsb": None}
        hibp_key = os.environ.get("HIBP_API_KEY")
        shodan_key = os.environ.get("SHODAN_API_KEY")
        gsb_key = os.environ.get("GSB_API_KEY")

        emails: set[str] = set()
        for f in findings:
            for email in EMAIL_RE.findall(f.context or ""):
                emails.add(email.lower())

        for email in sorted(emails)[:20]:
            external["emails"].append({"email": email, **cls.check_haveibeenpwned_email(email, hibp_key)})

        if shodan_key and findings:
            external["shodan"] = cls.check_shodan(findings[0].matched_text[:20], shodan_key)
        if gsb_key:
            external["gsb"] = cls.check_google_safe_browsing("https://example.com", gsb_key)

        verified: List[SecretFinding] = []
        for finding in findings:
            raw = vault.get(finding.raw_hash) if vault and finding.raw_hash else ""
            aws_secret = ""
            if finding.secret_type == "AWS_ACCESS_KEY":
                pair = pair_by_access_hash.get(finding.raw_hash) or pair_by_file.get(finding.file_path)
                if pair:
                    aws_secret = pair.get("secret", "")
                    if not raw:
                        raw = pair.get("access", "")
            verified.append(cls.verify_finding(finding, raw_value=raw, aws_secret=aws_secret))
        return verified, external


# ---------------------------------------------------------------------------
# Remediation + rotation
# ---------------------------------------------------------------------------


class RemediationPlanner:
    DEFAULT_PLAN = {
        "steps": [
            "Rotate or revoke the credential at the provider",
            "Remove from code and git history",
            "Update dependent systems",
            "Document the incident",
        ],
        "eta_hours": 2,
        "dependents": ["unknown — inventory usages"],
    }
    PLANS = {
        "AWS_ACCESS_KEY": {
            "steps": [
                "Disable the access key in IAM immediately",
                "Create a replacement key for legitimate services",
                "Update Secrets Manager / CI variables",
                "Review CloudTrail for unauthorized activity",
                "Delete the old key after cutover",
            ],
            "eta_hours": 2,
            "dependents": ["CI/CD", "servers with env vars", "IAM users/roles"],
        },
        "STRIPE_API_KEY": {
            "steps": [
                "Roll the secret key in Stripe Dashboard (or API if restricted key allows)",
                "Update payment services and webhooks",
                "Review recent charges for fraud",
            ],
            "eta_hours": 1,
            "dependents": ["billing service", "checkout"],
        },
        "GITHUB_TOKEN": {
            "steps": [
                "Revoke the PAT at github.com/settings/tokens",
                "Issue a scoped replacement token",
                "Update Actions secrets and local configs",
                "Audit recent access logs",
            ],
            "eta_hours": 1,
            "dependents": ["GitHub Actions", "bots", "developer machines"],
        },
        "DATABASE_PASSWORD": {
            "steps": [
                "Rotate DB password",
                "Update connection strings / secret stores",
                "Recycle app connection pools",
                "Audit DB logs",
            ],
            "eta_hours": 3,
            "dependents": ["app servers", "migrations", "analytics"],
        },
        "PRIVATE_KEY_PEM": {
            "steps": [
                "Assume key material is compromised",
                "Generate a new key pair",
                "Replace authorized keys / certificates",
                "Revoke associated certificates",
            ],
            "eta_hours": 4,
            "dependents": ["SSH hosts", "TLS", "CI deploy keys"],
        },
        "SLACK_BOT_TOKEN": {
            "steps": [
                "Revoke bot token in Slack app settings",
                "Reinstall app / issue new token",
                "Update deployment secrets",
            ],
            "eta_hours": 1,
            "dependents": ["Slack bots", "alert integrations"],
        },
    }

    @classmethod
    def plan_for(cls, finding: SecretFinding) -> str:
        plan = cls.PLANS.get(finding.secret_type, cls.DEFAULT_PLAN)
        lines = [
            f"ETA ~{plan['eta_hours']}h",
            "Dependents: " + ", ".join(plan["dependents"]),
            "Steps:",
        ]
        lines.extend(f"  {i}. {s}" for i, s in enumerate(plan["steps"], 1))
        lines.append("Minimize downtime: dual-write new secret → cut over → revoke old.")
        lines.append("Audit trail: ticket ID, rotator, timestamp, systems updated.")
        return "\n".join(lines)

    @classmethod
    def full_report(cls, findings: List[SecretFinding]) -> Dict[str, Any]:
        return {
            "generated_at": _now_iso(),
            "total": len(findings),
            "items": [
                {
                    "secret_type": f.secret_type,
                    "severity": f.severity,
                    "file": f.file_path,
                    "status": f.key_status,
                    "damage_scope": f.damage_scope,
                    "remediation": f.remediation or cls.plan_for(f),
                    "rotation_result": f.rotation_result,
                }
                for f in findings
            ],
        }


class RotationEngine:
    """
    Live rotation helpers. Default is dry-run.
    Requires admin/provider credentials via environment variables.
    """

    def __init__(self, execute: bool = False) -> None:
        self.execute = execute
        self.rollback_log: List[Dict[str, Any]] = []

    def rotate_finding(self, finding: SecretFinding, raw: str = "") -> str:
        handlers = {
            "GITHUB_TOKEN": self._rotate_github,
            "STRIPE_API_KEY": self._rotate_stripe,
            "AWS_ACCESS_KEY": self._rotate_aws_secrets_manager,
            "SLACK_BOT_TOKEN": self._rotate_slack,
            "ENV_SECRET_VALUE": self._rotate_vault_kv,
            "DATABASE_PASSWORD": self._rotate_vault_kv,
            "API_KEY_GENERIC": self._rotate_vault_kv,
        }
        handler = handlers.get(finding.secret_type, self._rotate_vault_kv)
        return handler(finding, raw)

    def _rotate_github(self, finding: SecretFinding, raw: str) -> str:
        # Self-revoke is not always possible; use GITHUB_ADMIN_TOKEN to delete fine-grained tokens
        # For exposed PAT: best effort auth.test-style — instruct manual revoke
        if not self.execute:
            return (
                "DRY-RUN: would revoke GitHub token and notify. "
                "Set --execute-rotation and GITHUB_ADMIN_TOKEN for assisted revoke."
            )
        admin = os.environ.get("GITHUB_ADMIN_TOKEN")
        if not admin:
            return "SKIPPED: set GITHUB_ADMIN_TOKEN to revoke via API; revoke manually at github.com/settings/tokens"
        # Attempt to verify exposed token then document — GitHub does not allow arbitrary PAT delete without app credentials
        check = CompromiseVerifier.check_github_token_active(raw) if raw else {}
        self.rollback_log.append({"type": "GITHUB_TOKEN", "hash": finding.raw_hash, "action": "manual_revoke_required"})
        return f"EXECUTED check only (status={check.get('status')}). Revoke manually; GitHub PAT delete needs OAuth app."

    def _rotate_stripe(self, finding: SecretFinding, raw: str) -> str:
        if not self.execute:
            return "DRY-RUN: would roll Stripe key via Dashboard/API. Set --execute-rotation + STRIPE_RESTRICTED_KEY."
        # Stripe rolling secret keys is Dashboard-first; restricted keys vary by account
        return "SKIPPED: Stripe key roll requires Dashboard or account-specific API; update services after roll."

    def _rotate_slack(self, finding: SecretFinding, raw: str) -> str:
        if not self.execute:
            return "DRY-RUN: would revoke Slack token via auth.revoke."
        if not raw or _is_redacted(raw):
            return "SKIPPED: no raw Slack token in vault"
        try:
            req = urllib.request.Request(
                "https://slack.com/api/auth.revoke",
                data=urllib.parse.urlencode({"token": raw}).encode(),
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())
            self.rollback_log.append({"type": "SLACK_BOT_TOKEN", "hash": finding.raw_hash, "revoked": data.get("ok")})
            return f"EXECUTED Slack auth.revoke ok={data.get('ok')} error={data.get('error')}"
        except Exception as exc:  # noqa: BLE001
            return f"FAILED Slack revoke: {exc}"

    def _rotate_aws_secrets_manager(self, finding: SecretFinding, raw: str) -> str:
        """Rotate via Secrets Manager using admin AWS keys from environment."""
        admin_ak = os.environ.get("AWS_ACCESS_KEY_ID")
        admin_sk = os.environ.get("AWS_SECRET_ACCESS_KEY")
        secret_id = os.environ.get("AWS_SECRETS_MANAGER_ID")
        region = os.environ.get("AWS_REGION", "us-east-1")
        if not self.execute:
            return (
                "DRY-RUN: would call secretsmanager:RotateSecret / PutSecretValue. "
                "Set --execute-rotation, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SECRETS_MANAGER_ID."
            )
        if not (admin_ak and admin_sk and secret_id):
            return "SKIPPED: missing AWS admin env vars for Secrets Manager rotation"
        # PutSecretValue with a generated placeholder rotation marker (real rotation uses Lambda)
        new_value = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
        target = f"https://secretsmanager.{region}.amazonaws.com/"
        payload = json.dumps(
            {
                "SecretId": secret_id,
                "SecretString": json.dumps({"rotated_at": _now_iso(), "value": new_value}),
            }
        )
        status, body = AWSSigner.request(
            admin_ak,
            admin_sk,
            "POST",
            target,
            region,
            "secretsmanager",
            payload=payload,
            extra_headers={
                "Content-Type": "application/x-amz-json-1.1",
                "X-Amz-Target": "secretsmanager.PutSecretValue",
            },
        )
        self.rollback_log.append(
            {
                "type": "AWS_SECRETS_MANAGER",
                "secret_id": secret_id,
                "previous_note": "Store previous SecretString before PutSecretValue for rollback",
                "http": status,
            }
        )
        if status == 200:
            return f"EXECUTED Secrets Manager PutSecretValue on {secret_id}"
        return f"FAILED Secrets Manager HTTP {status}: {body[:300]}"

    def _rotate_vault_kv(self, finding: SecretFinding, raw: str) -> str:
        vault_addr = os.environ.get("VAULT_ADDR")
        vault_token = os.environ.get("VAULT_TOKEN")
        vault_path = os.environ.get("VAULT_KV_PATH", f"secret/data/rotated/{finding.secret_type.lower()}")
        if not self.execute:
            return (
                f"DRY-RUN: would PUT {vault_path} via Vault KV. "
                "Set --execute-rotation, VAULT_ADDR, VAULT_TOKEN."
            )
        if not (vault_addr and vault_token):
            return "SKIPPED: set VAULT_ADDR and VAULT_TOKEN"
        new_value = base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip("=")
        url = vault_addr.rstrip("/") + "/" + vault_path.lstrip("/")
        # KV v2 style
        if "/data/" not in url and "secret/" in url:
            url = url.replace("secret/", "secret/data/", 1)
        body = json.dumps({"data": {"value": new_value, "rotated_from_hash": finding.raw_hash, "at": _now_iso()}})
        try:
            req = urllib.request.Request(
                url,
                data=body.encode(),
                method="POST",
                headers={"X-Vault-Token": vault_token, "Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                status = response.status
            self.rollback_log.append({"type": "VAULT_KV", "path": vault_path, "http": status, "new_preview": _redact(new_value)})
            return f"EXECUTED Vault KV write → {vault_path} (HTTP {status})"
        except Exception as exc:  # noqa: BLE001
            return f"FAILED Vault write: {exc}"

    def notify_developers(self, findings: List[SecretFinding]) -> bool:
        return AlertNotifier.send_slack(findings) or AlertNotifier.send_email(findings)


# ---------------------------------------------------------------------------
# Alerts / reporting / hooks / CI (same as before, extended)
# ---------------------------------------------------------------------------


class AlertNotifier:
    @staticmethod
    def format_message(findings: List[SecretFinding]) -> str:
        critical = sum(1 for f in findings if f.severity == "CRITICAL")
        high = sum(1 for f in findings if f.severity == "HIGH")
        lines = [
            f"KeyScan alert: {len(findings)} finding(s) ({critical} CRITICAL, {high} HIGH)",
            "",
        ]
        for f in findings[:20]:
            author = f" by {f.commit_author}" if f.commit_author else ""
            status = f" [{f.key_status}]" if f.key_status != "unknown" else ""
            lines.append(
                f"- [{f.severity}] {f.secret_type} in {f.file_path} "
                f"(line {f.line_number or 'n/a'}){author}{status}"
            )
        if len(findings) > 20:
            lines.append(f"... and {len(findings) - 20} more")
        lines.append("")
        lines.append("Remediation: rotate credentials, purge history, re-scan.")
        return "\n".join(lines)

    @classmethod
    def send_slack(cls, findings: List[SecretFinding], webhook_url: Optional[str] = None) -> bool:
        webhook_url = webhook_url or os.environ.get("SLACK_WEBHOOK_URL")
        if not webhook_url or not findings:
            return False
        try:
            req = urllib.request.Request(
                webhook_url,
                data=json.dumps({"text": cls.format_message(findings)}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                return 200 <= response.status < 300
        except Exception as exc:  # noqa: BLE001
            _warn(f"Slack notify failed: {exc}")
            return False

    @classmethod
    def send_email(
        cls,
        findings: List[SecretFinding],
        to_addr: Optional[str] = None,
        from_addr: Optional[str] = None,
        smtp_host: Optional[str] = None,
    ) -> bool:
        to_addr = to_addr or os.environ.get("SECURITY_ALERT_EMAIL")
        from_addr = from_addr or os.environ.get("SMTP_FROM", "secrets-scanner@localhost")
        smtp_host = smtp_host or os.environ.get("SMTP_HOST")
        if not to_addr or not smtp_host or not findings:
            return False
        msg = MIMEText(cls.format_message(findings))
        msg["Subject"] = f"[KeyScan] {len(findings)} finding(s)"
        msg["From"] = from_addr
        msg["To"] = to_addr
        try:
            port = int(os.environ.get("SMTP_PORT", "25"))
            user, password = os.environ.get("SMTP_USER"), os.environ.get("SMTP_PASSWORD")
            with smtplib.SMTP(smtp_host, port, timeout=15) as server:
                if os.environ.get("SMTP_STARTTLS", "").lower() in {"1", "true", "yes"}:
                    server.starttls()
                if user and password:
                    server.login(user, password)
                server.sendmail(from_addr, [to_addr], msg.as_string())
            return True
        except Exception as exc:  # noqa: BLE001
            _warn(f"Email notify failed: {exc}")
            return False


class SecretReporter:
    def __init__(
        self,
        findings: List[SecretFinding],
        timeline: Optional[List[TimelineEntry]] = None,
        cleanup: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.findings = findings
        self.timeline = timeline or []
        self.cleanup = cleanup

    def generate_json_report(self) -> str:
        report: Dict[str, Any] = {
            "scan_date": _now_iso(),
            "total_findings": len(self.findings),
            "findings_by_type": dict(Counter(f.secret_type for f in self.findings)),
            "findings_by_severity": dict(Counter(f.severity for f in self.findings)),
            "findings": [asdict(f) for f in self.findings],
            "timeline": [asdict(t) for t in self.timeline],
            "history_cleanup": self.cleanup or HistoryCleanup.generate_removal_plan(self.findings),
        }
        return json.dumps(report, indent=2, default=str)

    def generate_markdown_report(self) -> str:
        lines = [
            "# Secrets Exposure Report",
            f"Generated: {_now_iso()}",
            "",
            "## Summary",
            f"- Total Findings: {len(self.findings)}",
            "",
            "### Findings by Severity",
        ]
        severity_counts = Counter(f.severity for f in self.findings)
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if severity in severity_counts:
                lines.append(f"- {severity}: {severity_counts[severity]}")
        lines.extend(["", "### Findings by Type"])
        for secret_type, count in sorted(Counter(f.secret_type for f in self.findings).items()):
            lines.append(f"- {secret_type}: {count}")

        if self.timeline:
            lines.extend(["", "## Secrets Timeline (git history)"])
            for t in self.timeline:
                lines.append(
                    f"- **{t.secret_type}** `{t.matched_preview}` in `{t.file_path}` — "
                    f"first `{t.first_commit}` ({t.first_date}) by {t.first_author}; "
                    f"last `{t.last_commit}`; in {t.commit_count} commit(s)"
                )

        lines.extend(["", "## Detailed Findings"])
        for finding in sorted(
            self.findings, key=lambda x: (SEVERITY_ORDER.get(x.severity, 9), x.secret_type)
        ):
            lines.append(f"### {finding.secret_type}")
            lines.append(f"- **Severity:** {finding.severity}")
            lines.append(f"- **File:** {finding.file_path}")
            lines.append(f"- **Line:** {finding.line_number or 'N/A'}")
            lines.append(f"- **Source:** {finding.source}")
            lines.append(f"- **Match:** `{finding.matched_text}`")
            if finding.entropy is not None:
                lines.append(f"- **Entropy:** {finding.entropy}")
            if finding.damage_scope:
                lines.append(f"- **Damage scope:** {finding.damage_scope}")
            if finding.commit_hash:
                lines.append(f"- **Commit:** `{finding.commit_hash[:12]}` by {finding.commit_author}")
            if finding.key_status and finding.key_status != "unknown":
                lines.append(f"- **Key status:** {finding.key_status}")
            if finding.is_compromised:
                lines.append(f"- **COMPROMISED:** {finding.compromise_evidence}")
            elif finding.compromise_evidence:
                lines.append(f"- **Evidence:** {finding.compromise_evidence}")
            if finding.remediation:
                lines.append(f"- **Remediation:**\n```\n{finding.remediation}\n```")
            if finding.rotation_result:
                lines.append(f"- **Rotation:** {finding.rotation_result}")
            lines.append("")

        cleanup = self.cleanup or HistoryCleanup.generate_removal_plan(self.findings)
        lines.extend(["## History Cleanup", cleanup["warning"], "", "### Checklist"])
        lines.extend(f"- {item}" for item in cleanup["checklist"])
        lines.extend(["", "### BFG commands", "```"])
        lines.extend(cleanup["bfg_commands"])
        lines.extend(["```", "", "### filter-repo", "```"])
        lines.extend(cleanup.get("filter_repo_commands", cleanup.get("filter_branch_fallback", [])))
        lines.append("```")
        return "\n".join(lines)


class PreCommitHook:
    @staticmethod
    def generate_pre_commit_hook(scanner_path: Optional[str] = None) -> str:
        script_ref = scanner_path or "keyscan.py"
        return f"""#!/bin/bash
# Pre-commit hook: block commits that introduce secrets
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
SCANNER="$ROOT/{script_ref}"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

if [[ -f "$SCANNER" ]]; then
  git diff --cached --name-only -z | while IFS= read -r -d '' file; do
    [[ -f "$file" ]] || continue
    mkdir -p "$TMPDIR/$(dirname "$file")"
    git show ":$file" > "$TMPDIR/$file" 2>/dev/null || true
  done
  python3 "$SCANNER" scan --repo "$TMPDIR" -o "$TMPDIR/out" --no-alert --no-entropy >/dev/null 2>&1 || true
  FINDINGS="$TMPDIR/out/secrets-report.json"
  if [[ -f "$FINDINGS" ]]; then
    COUNT=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('total_findings',0))" "$FINDINGS")
    if [[ "${{COUNT:-0}}" -gt 0 ]]; then
      echo "COMMIT BLOCKED: $COUNT potential secret(s) in staged changes"
      echo "Review: $FINDINGS"
      echo "Emergency bypass (discouraged): git commit --no-verify"
      exit 1
    fi
  fi
fi

PATTERNS=(
  'AKIA[0-9A-Z]{{16}}'
  'sk_live_[0-9a-zA-Z]{{20,}}'
  'sk_test_[0-9a-zA-Z]{{20,}}'
  'gh[pousr]_[A-Za-z0-9_]{{36,}}'
  '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'
)
while IFS= read -r file; do
  [[ -z "$file" || ! -f "$file" ]] && continue
  for pattern in "${{PATTERNS[@]}}"; do
    if git show ":$file" 2>/dev/null | grep -Eq "$pattern"; then
      echo "COMMIT BLOCKED: Potential secret in $file"
      echo "  Pattern: $pattern"
      echo "  Emergency bypass (discouraged): git commit --no-verify"
      exit 1
    fi
  done
done < <(git diff --cached --name-only)
exit 0
"""

    @staticmethod
    def install_hook(repo_path: str = ".", scanner_path: Optional[str] = None) -> bool:
        try:
            hook_dir = Path(repo_path) / ".git" / "hooks"
            hook_path = hook_dir / "pre-commit"
            if not hook_dir.exists():
                print(f"Error: .git/hooks not found in {repo_path}", file=sys.stderr)
                return False
            hook_path.write_text(PreCommitHook.generate_pre_commit_hook(scanner_path), encoding="utf-8")
            os.chmod(hook_path, 0o755)
            print(f"[+] Pre-commit hook installed at {hook_path}")
            return True
        except OSError as exc:
            print(f"Error installing pre-commit hook: {exc}", file=sys.stderr)
            return False


class CICDIntegration:
    @staticmethod
    def write_workflow(repo_path: str = ".") -> Path:
        path = Path(repo_path) / ".github" / "workflows" / "secrets-scan.yml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            """name: KeyScan

on:
  push:
    branches: [main, master]
  pull_request:
  schedule:
    - cron: "0 6 * * 1"

permissions:
  contents: read
  issues: write
  pull-requests: write

jobs:
  secrets-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Full scan
        run: python keyscan.py scan-all --repo . -o secrets-report --no-alert --store-raw

      - name: Fail on CRITICAL/HIGH
        run: |
          python <<'PY'
          import json, os, pathlib, sys
          bad, lines = 0, []
          for name in ("secrets-report.json", "history-report.json"):
              path = pathlib.Path("secrets-report") / name
              if not path.exists():
                  continue
              for f in json.loads(path.read_text()).get("findings", []):
                  if f.get("severity") in ("CRITICAL", "HIGH"):
                      bad += 1
                      lines.append(f"- [{f['severity']}] {f['secret_type']} in {f['file_path']}")
          pathlib.Path(os.environ["GITHUB_STEP_SUMMARY"]).write_text(
              f"## Secrets scan\\nFindings CRITICAL/HIGH: {bad}\\n\\n" + "\\n".join(lines[:50])
          )
          raise SystemExit(1 if bad else 0)
          PY

      - name: Create issue on failure
        if: failure() && github.event_name != 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const title = `Secrets scan failed on ${context.sha}`;
            const body = [
              "Automated secrets scan found CRITICAL/HIGH findings.",
              "",
              `Workflow: ${context.serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId}`,
            ].join("\\n");
            const issues = await github.rest.issues.listForRepo({
              owner: context.repo.owner,
              repo: context.repo.repo,
              state: "open",
              labels: "security",
            });
            if (!issues.data.find(i => i.title === title)) {
              await github.rest.issues.create({
                owner: context.repo.owner,
                repo: context.repo.repo,
                title,
                body,
                labels: ["security"],
              });
            }
""",
            encoding="utf-8",
        )
        return path


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------


def _load_findings(path: Path) -> List[SecretFinding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    findings: List[SecretFinding] = []
    for item in data.get("findings", []):
        findings.append(
            SecretFinding(
                secret_type=item.get("secret_type", "UNKNOWN"),
                severity=item.get("severity", "HIGH"),
                file_path=item.get("file_path", ""),
                line_number=item.get("line_number"),
                matched_text=item.get("matched_text", ""),
                context=item.get("context", ""),
                source=item.get("source", "current_code"),
                commit_hash=item.get("commit_hash"),
                commit_author=item.get("commit_author"),
                commit_date=item.get("commit_date"),
                raw_hash=item.get("raw_hash", ""),
                entropy=item.get("entropy"),
                is_compromised=bool(item.get("is_compromised")),
                compromise_evidence=item.get("compromise_evidence", ""),
                key_status=item.get("key_status", "unknown"),
                damage_scope=item.get("damage_scope", ""),
                remediation=item.get("remediation", ""),
                rotation_result=item.get("rotation_result", ""),
            )
        )
    return findings


def _has_high_severity(findings: Iterable[SecretFinding]) -> bool:
    return any(f.severity in ("CRITICAL", "HIGH") for f in findings)


def _maybe_alert(findings: List[SecretFinding], no_alert: bool) -> None:
    if no_alert or not findings:
        return
    AlertNotifier.send_slack(findings)
    AlertNotifier.send_email(findings)


def _write_scan_reports(reporter: SecretReporter, output_dir: Path, stem: str) -> None:
    (output_dir / f"{stem}.json").write_text(reporter.generate_json_report(), encoding="utf-8")
    (output_dir / f"{stem}.md").write_text(reporter.generate_markdown_report(), encoding="utf-8")


def _run_code_scan(args: argparse.Namespace) -> Tuple[List[SecretFinding], SecretScanner]:
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    vault_path = out_dir / ".secrets-vault.json"
    scanner = SecretScanner(args.repo, store_raw=args.store_raw, vault_path=vault_path)
    findings = scanner.scan_current_code(entropy=not args.no_entropy)
    findings.extend(scanner.scan_env_file())
    findings.extend(scanner.scan_requirements())
    findings.extend(scanner.scan_dockerfile())
    if args.store_raw:
        scanner.vault.save()
    return findings, scanner


def main() -> None:
    parser = argparse.ArgumentParser(description="KeyScan — secrets & git history scanner")
    parser.add_argument(
        "action",
        choices=[
            "scan",
            "scan-history",
            "scan-all",
            "verify-compromise",
            "rotate",
            "install-hook",
            "install-ci",
            "notify",
        ],
        help="Action to perform",
    )
    parser.add_argument("--repo", default=".", help="Repository path")
    parser.add_argument("--commits", type=int, default=500, help="Max commits to scan")
    parser.add_argument("-o", "--output", default="secrets-report", help="Output directory or .json file")
    parser.add_argument("-f", "--findings", default=None, help="Path to secrets-report.json")
    parser.add_argument("--include-merges", action="store_true", help="Include merge commits")
    parser.add_argument("--no-alert", action="store_true", help="Skip Slack/email alerts")
    parser.add_argument(
        "--store-raw",
        action="store_true",
        help="Store raw secrets in .secrets-vault.json (mode 0600) for live verification/rotation",
    )
    parser.add_argument("--no-entropy", action="store_true", help="Disable high-entropy heuristic")
    parser.add_argument(
        "--execute-rotation",
        action="store_true",
        help="Actually call provider APIs to rotate/revoke (default: dry-run)",
    )
    args = parser.parse_args()

    output_is_file = str(args.output).endswith(".json")
    if not output_is_file:
        os.makedirs(args.output, exist_ok=True)
    exit_code = 0

    if args.action == "scan":
        print("[*] Scanning current code for secrets...")
        findings, scanner = _run_code_scan(args)
        print(f"[+] Found {len(findings)} potential secret(s)")
        if scanner.aws_credential_pairs():
            print(f"[+] AWS key pairs detected in {len(scanner.aws_credential_pairs())} file(s)")
        reporter = SecretReporter(findings)
        _write_scan_reports(reporter, Path(args.output), "secrets-report")
        # Persist pairs metadata (no secrets) for verify
        pairs_meta = [
            {"file_path": p["file_path"], "access_hash": p.get("access_hash"), "secret_hash": p.get("secret_hash")}
            for p in scanner.aws_credential_pairs()
        ]
        if args.store_raw:
            # Keep full pairs only inside vault file already; write hash index
            (Path(args.output) / "aws-pairs.json").write_text(
                json.dumps(
                    [
                        {
                            "file_path": p["file_path"],
                            "access_hash": p.get("access_hash"),
                            "secret_hash": p.get("secret_hash"),
                            "access": p.get("access"),
                            "secret": p.get("secret"),
                        }
                        for p in scanner.aws_credential_pairs()
                    ],
                    indent=2,
                ),
                encoding="utf-8",
            )
            try:
                os.chmod(Path(args.output) / "aws-pairs.json", 0o600)
            except OSError:
                pass
        else:
            (Path(args.output) / "aws-pairs.json").write_text(json.dumps(pairs_meta, indent=2), encoding="utf-8")
        _maybe_alert(findings, args.no_alert)
        if _has_high_severity(findings):
            exit_code = 1

    elif args.action == "scan-history":
        print("[*] Scanning git history for secrets...")
        out_dir = Path(args.output)
        vault = SecretVault(out_dir / ".secrets-vault.json")
        scanner = SecretScanner(args.repo, store_raw=args.store_raw, vault_path=out_dir / ".secrets-vault.json")
        findings = scanner.scan_git_history(
            commit_limit=args.commits,
            skip_merges=not args.include_merges,
            entropy=not args.no_entropy,
        )
        if args.store_raw:
            scanner.vault.save()
        timeline = scanner.build_timeline(findings)
        print(f"[+] Found {len(findings)} secret(s) in git history ({len(timeline)} timeline entries)")
        cleanup = HistoryCleanup.generate_removal_plan(findings, scanner.vault if args.store_raw else None)
        reporter = SecretReporter(findings, timeline=timeline, cleanup=cleanup)
        _write_scan_reports(reporter, out_dir, "history-report")
        (out_dir / "history-cleanup.json").write_text(json.dumps(cleanup, indent=2), encoding="utf-8")
        if args.store_raw:
            n = HistoryCleanup.write_secrets_file(out_dir / "secrets-to-remove.txt", findings, scanner.vault)
            print(f"[+] Wrote {n} exact secret(s) to secrets-to-remove.txt")
        _maybe_alert(findings, args.no_alert)
        if _has_high_severity(findings):
            exit_code = 1

    elif args.action == "scan-all":
        print("[*] Running full scan (code + history + verify)...")
        # reuse scan + history + verify
        sys.argv = [
            sys.argv[0],
            "scan",
            "--repo",
            args.repo,
            "-o",
            args.output,
            *(["--store-raw"] if args.store_raw else []),
            *(["--no-alert"] if args.no_alert else []),
            *(["--no-entropy"] if args.no_entropy else []),
        ]
        # inline to preserve exit aggregation
        findings, scanner = _run_code_scan(args)
        hist_scanner = SecretScanner(
            args.repo, store_raw=args.store_raw, vault_path=Path(args.output) / ".secrets-vault.json"
        )
        # merge vaults
        hist_scanner.vault._data.update(scanner.vault._data)
        history = hist_scanner.scan_git_history(
            commit_limit=args.commits,
            skip_merges=not args.include_merges,
            entropy=False,
        )
        if args.store_raw:
            hist_scanner.vault._data.update(scanner.vault._data)
            hist_scanner.vault.save()
        timeline = hist_scanner.build_timeline(history)
        cleanup = HistoryCleanup.generate_removal_plan(history, hist_scanner.vault if args.store_raw else None)
        _write_scan_reports(SecretReporter(findings), Path(args.output), "secrets-report")
        _write_scan_reports(
            SecretReporter(history, timeline=timeline, cleanup=cleanup), Path(args.output), "history-report"
        )
        (Path(args.output) / "history-cleanup.json").write_text(json.dumps(cleanup, indent=2), encoding="utf-8")

        vault = hist_scanner.vault
        aws_pairs = scanner.aws_credential_pairs()
        # reload secrets from vault into pairs if needed
        verified, external = CompromiseVerifier.verify_all(findings + history, vault=vault, aws_pairs=aws_pairs)
        report = {
            "verified_at": _now_iso(),
            "total": len(verified),
            "active": sum(1 for f in verified if f.key_status == "active"),
            "pwned": sum(1 for f in verified if f.key_status == "pwned"),
            "findings": [asdict(f) for f in verified],
            "remediation": RemediationPlanner.full_report(verified),
            "external_checks": external,
        }
        (Path(args.output) / "compromise-status.json").write_text(
            json.dumps(report, indent=2, default=str), encoding="utf-8"
        )
        print(f"[+] Code findings: {len(findings)} | History: {len(history)} | Active: {report['active']}")
        _maybe_alert(verified, args.no_alert)
        if _has_high_severity(verified):
            exit_code = 1

    elif args.action == "verify-compromise":
        print("[*] Verifying compromise status...")
        findings_path = Path(args.findings) if args.findings else Path(args.output) / "secrets-report.json"
        if not findings_path.exists():
            alt = Path(args.output) / "secrets-report.json" if not output_is_file else None
            if alt and alt.exists():
                findings_path = alt
            else:
                print(f"Error: findings file not found: {findings_path}", file=sys.stderr)
                sys.exit(1)

        findings = _load_findings(findings_path)
        vault_path = findings_path.parent / ".secrets-vault.json"
        vault = SecretVault(vault_path) if vault_path.exists() else None
        aws_pairs: List[Dict[str, str]] = []
        pairs_path = findings_path.parent / "aws-pairs.json"
        if pairs_path.exists():
            try:
                aws_pairs = json.loads(pairs_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass

        verified, external = CompromiseVerifier.verify_all(findings, vault=vault, aws_pairs=aws_pairs)
        report = {
            "verified_at": _now_iso(),
            "total": len(verified),
            "active": sum(1 for f in verified if f.key_status == "active"),
            "pwned": sum(1 for f in verified if f.key_status == "pwned"),
            "findings": [asdict(f) for f in verified],
            "remediation": RemediationPlanner.full_report(verified),
            "external_checks": external,
        }
        if output_is_file:
            out = Path(args.output)
            out.parent.mkdir(parents=True, exist_ok=True)
        else:
            out = Path(args.output) / "compromise-status.json"
        out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        print(f"[+] Verification complete → {out}")
        print(f"    Active: {report['active']} | Pwned passwords: {report['pwned']}")

    elif args.action == "rotate":
        print("[*] Running rotation engine...")
        findings_path = Path(args.findings) if args.findings else Path(args.output) / "compromise-status.json"
        if not findings_path.exists():
            findings_path = Path(args.output) / "secrets-report.json"
        if not findings_path.exists():
            print(f"Error: findings file not found: {findings_path}", file=sys.stderr)
            sys.exit(1)
        findings = _load_findings(findings_path)
        vault = SecretVault(findings_path.parent / ".secrets-vault.json")
        engine = RotationEngine(execute=args.execute_rotation)
        mode = "EXECUTE" if args.execute_rotation else "DRY-RUN"
        print(f"[*] Mode: {mode}")
        for finding in findings:
            raw = vault.get(finding.raw_hash) if finding.raw_hash else ""
            finding.rotation_result = engine.rotate_finding(finding, raw)
            print(f"    {finding.secret_type} @ {finding.file_path}: {finding.rotation_result}")
        engine.notify_developers(findings)
        out = Path(args.output) / "rotation-report.json"
        if output_is_file:
            out = Path(args.output)
        out.write_text(
            json.dumps(
                {
                    "mode": mode,
                    "generated_at": _now_iso(),
                    "rollback_log": engine.rollback_log,
                    "results": [asdict(f) for f in findings],
                },
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )
        print(f"[+] Rotation report → {out}")

    elif args.action == "install-hook":
        print("[*] Installing pre-commit hook...")
        if not PreCommitHook.install_hook(args.repo, scanner_path="keyscan.py"):
            sys.exit(1)

    elif args.action == "install-ci":
        print("[*] Writing GitHub Actions workflow...")
        path = CICDIntegration.write_workflow(args.repo)
        print(f"[+] Wrote {path}")

    elif args.action == "notify":
        findings_path = Path(args.findings or Path(args.output) / "secrets-report.json")
        if not findings_path.exists():
            print(f"Error: findings file not found: {findings_path}", file=sys.stderr)
            sys.exit(1)
        findings = _load_findings(findings_path)
        print(f"[+] Slack: {'sent' if AlertNotifier.send_slack(findings) else 'skipped/failed'}")
        print(f"[+] Email: {'sent' if AlertNotifier.send_email(findings) else 'skipped/failed'}")

    if args.action in {"scan", "scan-history", "scan-all", "verify-compromise", "rotate"}:
        print(f"[+] Reports saved under {args.output}")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
