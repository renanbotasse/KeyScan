"""Command-line interface for KeyScan."""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import fields
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .alerts import AlertNotifier
from .cicd import CICDIntegration
from .history import HistoryCleanup
from .hooks import PreCommitHook
from .models import SecretFinding, TimelineEntry
from .remediation import RemediationPlanner
from .report import SecretReporter
from .rotation import RotationEngine
from .scanner import SecretScanner
from .util import _now_iso
from .vault import SecretVault
from .verify import CompromiseVerifier

_FINDING_FIELDS = {f.name for f in fields(SecretFinding)}
REPORT_MD = "report.md"
REPORT_JSON = "report.json"
VAULT_NAME = ".vault.json"


def _load_findings(path: Path) -> List[SecretFinding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    findings: List[SecretFinding] = []
    for item in data.get("findings", []):
        kwargs = {key: item[key] for key in _FINDING_FIELDS if key in item}
        findings.append(SecretFinding(**kwargs))
    return findings


def _has_high_severity(findings: Iterable[SecretFinding]) -> bool:
    return any(f.severity in ("CRITICAL", "HIGH") for f in findings)


def _maybe_alert(findings: List[SecretFinding], no_alert: bool) -> None:
    if no_alert or not findings:
        return
    AlertNotifier.send_slack(findings)
    AlertNotifier.send_email(findings)


def _vault_path(out_dir: Path) -> Path:
    return out_dir / VAULT_NAME


def _write_report(
    out_dir: Path,
    findings: List[SecretFinding],
    *,
    timeline: Optional[List[TimelineEntry]] = None,
    cleanup: Optional[Dict[str, Any]] = None,
    verification: Optional[Dict[str, Any]] = None,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    reporter = SecretReporter(
        findings,
        timeline=timeline,
        cleanup=cleanup,
        verification=verification,
    )
    (out_dir / REPORT_MD).write_text(reporter.generate_markdown_report(), encoding="utf-8")
    (out_dir / REPORT_JSON).write_text(reporter.generate_json_report(), encoding="utf-8")


def _verification_summary(verified: List[SecretFinding], external: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "verified_at": _now_iso(),
        "active": sum(1 for f in verified if f.key_status == "active"),
        "pwned": sum(1 for f in verified if f.key_status == "pwned"),
        "external_checks": external,
        "remediation": RemediationPlanner.full_report(verified),
    }


def _run_code_scan(args: argparse.Namespace) -> Tuple[List[SecretFinding], SecretScanner]:
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    scanner = SecretScanner(args.repo, store_raw=args.store_raw, vault_path=_vault_path(out_dir))
    findings = scanner.scan_current_code(entropy=bool(getattr(args, "entropy", False)))
    if getattr(args, "include_env", False):
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
    parser.add_argument("-o", "--output", default="secrets-report", help="Output directory")
    parser.add_argument("-f", "--findings", default=None, help="Path to report.json")
    parser.add_argument("--include-merges", action="store_true", help="Include merge commits")
    parser.add_argument("--no-alert", action="store_true", help="Skip Slack/email alerts")
    parser.add_argument(
        "--store-raw",
        action="store_true",
        help="Keep a private .vault.json for live verification (not for sharing)",
    )
    parser.add_argument(
        "--include-env",
        action="store_true",
        help="Also scan .env / *.env files (skipped by default — local secrets belong there)",
    )
    parser.add_argument(
        "--entropy",
        action="store_true",
        help="Enable high-entropy heuristic (noisy; off by default)",
    )
    parser.add_argument(
        "--no-entropy",
        action="store_true",
        help=argparse.SUPPRESS,  # kept for backwards compat; entropy is off by default
    )
    parser.add_argument(
        "--execute-rotation",
        action="store_true",
        help="Actually call provider APIs to rotate/revoke (default: dry-run)",
    )
    args = parser.parse_args()

    out_dir = Path(args.output)
    if not str(args.output).endswith(".json"):
        out_dir.mkdir(parents=True, exist_ok=True)
    exit_code = 0

    if args.action == "scan":
        print("[*] Scanning current code for secrets...")
        findings, _scanner = _run_code_scan(args)
        print(f"[+] Found {len(findings)} potential secret(s)")
        _write_report(out_dir, findings)
        _maybe_alert(findings, args.no_alert)
        if _has_high_severity(findings):
            exit_code = 1
        print(f"[+] Open {out_dir / REPORT_MD}")

    elif args.action == "scan-history":
        print("[*] Scanning git history for secrets...")
        scanner = SecretScanner(
            args.repo, store_raw=args.store_raw, vault_path=_vault_path(out_dir)
        )
        findings = scanner.scan_git_history(
            commit_limit=args.commits,
            skip_merges=not args.include_merges,
            entropy=bool(getattr(args, "entropy", False)),
        )
        if args.store_raw:
            scanner.vault.save()
        timeline = scanner.build_timeline(findings)
        cleanup = HistoryCleanup.generate_removal_plan(
            findings, scanner.vault if args.store_raw else None
        )
        print(f"[+] Found {len(findings)} secret(s) in git history")
        _write_report(out_dir, findings, timeline=timeline, cleanup=cleanup)
        _maybe_alert(findings, args.no_alert)
        if _has_high_severity(findings):
            exit_code = 1
        print(f"[+] Open {out_dir / REPORT_MD}")

    elif args.action == "scan-all":
        print("[*] Running full scan (code + history + verify)...")
        findings, scanner = _run_code_scan(args)
        hist_scanner = SecretScanner(
            args.repo, store_raw=args.store_raw, vault_path=_vault_path(out_dir)
        )
        hist_scanner.vault._data.update(scanner.vault._data)
        history = hist_scanner.scan_git_history(
            commit_limit=args.commits,
            skip_merges=not args.include_merges,
            entropy=False,
        )
        if args.store_raw:
            hist_scanner.vault.save()
        all_findings = findings + history
        timeline = hist_scanner.build_timeline(history)
        cleanup = HistoryCleanup.generate_removal_plan(
            history, hist_scanner.vault if args.store_raw else None
        )
        verified, external = CompromiseVerifier.verify_all(
            all_findings,
            vault=hist_scanner.vault,
            aws_pairs=scanner.aws_credential_pairs(),
        )
        verification = _verification_summary(verified, external)
        _write_report(
            out_dir,
            verified,
            timeline=timeline,
            cleanup=cleanup,
            verification=verification,
        )
        print(
            f"[+] Code: {len(findings)} | History: {len(history)} | "
            f"Active: {verification['active']} | Pwned: {verification['pwned']}"
        )
        _maybe_alert(verified, args.no_alert)
        if _has_high_severity(verified):
            exit_code = 1
        print(f"[+] Open {out_dir / REPORT_MD}")

    elif args.action == "verify-compromise":
        print("[*] Verifying compromise status...")
        findings_path = Path(args.findings) if args.findings else out_dir / REPORT_JSON
        if not findings_path.exists():
            print(f"Error: findings file not found: {findings_path}", file=sys.stderr)
            sys.exit(1)
        findings = _load_findings(findings_path)
        vault = SecretVault(_vault_path(findings_path.parent))
        verified, external = CompromiseVerifier.verify_all(findings, vault=vault, aws_pairs=[])
        verification = _verification_summary(verified, external)
        _write_report(findings_path.parent, verified, verification=verification)
        print(f"[+] Active: {verification['active']} | Pwned: {verification['pwned']}")
        print(f"[+] Open {findings_path.parent / REPORT_MD}")

    elif args.action == "rotate":
        print("[*] Running rotation engine...")
        findings_path = Path(args.findings) if args.findings else out_dir / REPORT_JSON
        if not findings_path.exists():
            print(f"Error: findings file not found: {findings_path}", file=sys.stderr)
            sys.exit(1)
        findings = _load_findings(findings_path)
        vault = SecretVault(_vault_path(findings_path.parent))
        engine = RotationEngine(execute=args.execute_rotation)
        mode = "EXECUTE" if args.execute_rotation else "DRY-RUN"
        print(f"[*] Mode: {mode}")
        for finding in findings:
            raw = vault.get(finding.raw_hash) if finding.raw_hash else ""
            finding.rotation_result = engine.rotate_finding(finding, raw)
            print(f"    {finding.secret_type} @ {finding.file_path}: {finding.rotation_result}")
        engine.notify_developers(findings)
        _write_report(findings_path.parent, findings)
        print(f"[+] Updated {findings_path.parent / REPORT_MD}")

    elif args.action == "install-hook":
        print("[*] Installing pre-commit hook...")
        if not PreCommitHook.install_hook(args.repo):
            sys.exit(1)

    elif args.action == "install-ci":
        print("[*] Writing GitHub Actions workflow...")
        path = CICDIntegration.write_workflow(args.repo)
        print(f"[+] Wrote {path}")

    elif args.action == "notify":
        findings_path = Path(args.findings or out_dir / REPORT_JSON)
        if not findings_path.exists():
            print(f"Error: findings file not found: {findings_path}", file=sys.stderr)
            sys.exit(1)
        findings = _load_findings(findings_path)
        print(f"[+] Slack: {'sent' if AlertNotifier.send_slack(findings) else 'skipped/failed'}")
        print(f"[+] Email: {'sent' if AlertNotifier.send_email(findings) else 'skipped/failed'}")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
