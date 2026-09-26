"""Slack/email alert notifications."""
from __future__ import annotations

import json
import os
import smtplib
import urllib.request
from email.mime.text import MIMEText
from typing import List, Optional

from .models import SecretFinding
from .util import _warn


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
