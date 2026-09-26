"""Remediation planning for exposed secrets."""
from __future__ import annotations

from typing import Any, Dict, List

from .models import SecretFinding
from .util import _now_iso


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
