"""JSON and Markdown report generation."""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from .constants import SEVERITY_ORDER
from .history import HistoryCleanup
from .models import SecretFinding, TimelineEntry
from .util import _now_iso


class SecretReporter:
    def __init__(
        self,
        findings: List[SecretFinding],
        timeline: Optional[List[TimelineEntry]] = None,
        cleanup: Optional[Dict[str, Any]] = None,
        verification: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.findings = findings
        self.timeline = timeline or []
        self.cleanup = cleanup
        self.verification = verification

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
        if self.verification:
            report["verification"] = self.verification
        return json.dumps(report, indent=2, default=str)

    def generate_markdown_report(self) -> str:
        lines = [
            "# KeyScan Report",
            f"Generated: {_now_iso()}",
            "",
            "## Summary",
            f"- Total findings: **{len(self.findings)}**",
            "",
        ]

        severity_counts = Counter(f.severity for f in self.findings)
        if severity_counts:
            lines.append("### By severity")
            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                if severity in severity_counts:
                    lines.append(f"- {severity}: {severity_counts[severity]}")
            lines.append("")

        type_counts = Counter(f.secret_type for f in self.findings)
        if type_counts:
            lines.append("### By type")
            for secret_type, count in sorted(type_counts.items()):
                lines.append(f"- {secret_type}: {count}")
            lines.append("")

        if self.verification:
            lines.append("### Live checks")
            lines.append(f"- Active keys: {self.verification.get('active', 0)}")
            lines.append(f"- Pwned passwords: {self.verification.get('pwned', 0)}")
            lines.append("")

        code = [f for f in self.findings if f.source != "git_history"]
        history = [f for f in self.findings if f.source == "git_history"]

        if code:
            lines.extend(["## Current code", ""])
            lines.extend(self._finding_blocks(code))

        if history:
            lines.extend(["## Git history", ""])
            if self.timeline:
                lines.append("### Timeline")
                for t in self.timeline:
                    lines.append(
                        f"- **{t.secret_type}** `{t.matched_preview}` in `{t.file_path}` — "
                        f"first `{t.first_commit}` ({t.first_date}); "
                        f"last `{t.last_commit}`; {t.commit_count} commit(s)"
                    )
                lines.append("")
            lines.extend(self._finding_blocks(history))

        if not self.findings:
            lines.append("No secrets found.")
            lines.append("")

        cleanup = self.cleanup or HistoryCleanup.generate_removal_plan(self.findings)
        if history:
            lines.extend(["## How to clean git history", cleanup["warning"], ""])
            lines.extend(f"- {item}" for item in cleanup["checklist"])
            lines.append("")

        return "\n".join(lines)

    def _finding_blocks(self, findings: List[SecretFinding]) -> List[str]:
        lines: List[str] = []
        for finding in sorted(
            findings, key=lambda x: (SEVERITY_ORDER.get(x.severity, 9), x.secret_type)
        ):
            lines.append(f"### [{finding.severity}] {finding.secret_type}")
            lines.append(f"- **File:** `{finding.file_path}` (line {finding.line_number or 'n/a'})")
            lines.append(f"- **Match:** `{finding.matched_text}`")
            if finding.commit_hash:
                lines.append(f"- **Commit:** `{finding.commit_hash[:12]}` by {finding.commit_author}")
            if finding.key_status and finding.key_status != "unknown":
                lines.append(f"- **Status:** {finding.key_status}")
            if finding.compromise_evidence:
                label = "COMPROMISED" if finding.is_compromised else "Check"
                lines.append(f"- **{label}:** {finding.compromise_evidence}")
            if finding.damage_scope:
                lines.append(f"- **Risk:** {finding.damage_scope}")
            lines.append("")
        return lines
