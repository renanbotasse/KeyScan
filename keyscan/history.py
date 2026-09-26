"""Git history cleanup helpers."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import SecretFinding
from .util import _chmod_private
from .vault import SecretVault


class HistoryCleanup:
    @staticmethod
    def generate_removal_plan(findings: List[SecretFinding], vault: Optional[SecretVault] = None) -> Dict[str, Any]:
        exact: List[str] = []
        if vault:
            for f in findings:
                if f.source == "git_history" and f.raw_hash:
                    raw = vault.get(f.raw_hash)
                    if raw:
                        exact.append(raw)
        paths = sorted({f.file_path for f in findings if f.source == "git_history" and f.file_path})
        history_count = sum(1 for f in findings if f.source == "git_history")
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
            "secrets_count": len(exact) or history_count,
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
        _chmod_private(path)
        return len(lines)
