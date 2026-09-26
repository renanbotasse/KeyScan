"""Credential rotation helpers (dry-run by default)."""
from __future__ import annotations

import base64
import json
import os
import urllib.parse
import urllib.request
from typing import Any, Dict, List

from .alerts import AlertNotifier
from .aws import AWSSigner
from .models import SecretFinding
from .util import _is_redacted, _now_iso, _redact
from .verify import CompromiseVerifier


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
