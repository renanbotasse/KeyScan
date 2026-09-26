"""Shared constants for scanning and reporting."""
from __future__ import annotations

import re


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
    "keyscan",  # don't scan the scanner itself
    "sbom-report",
    "sbombpath-report",
    "htmlcov",
    "coverage",
    "migrations",  # Django migration dependency names cause noise
}
SKIP_FILES = {
    "keyscan.py",
    "KeyScan_Documentation.md",
    "README.md",
}


def _is_env_file(name: str) -> bool:
    """True for local dotenv files (.env, .env.local, .sbombox.env, …)."""
    lower = name.lower()
    return lower.startswith(".env") or lower.endswith(".env") or ".env." in lower

SCAN_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
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
