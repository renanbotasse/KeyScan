"""Pre-commit hook generation and installation."""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional


class PreCommitHook:
    @staticmethod
    def generate_pre_commit_hook(scanner_path: Optional[str] = None) -> str:
        # scanner_path kept for API compatibility; hook invokes python -m keyscan
        script_ref = scanner_path or "keyscan.py"
        return f"""#!/bin/bash
# Pre-commit hook: block commits that introduce secrets
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
export PYTHONPATH="$ROOT${{PYTHONPATH:+:$PYTHONPATH}}"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

if [[ -d "$ROOT/keyscan" || -f "$ROOT/{script_ref}" ]]; then
  git diff --cached --name-only -z | while IFS= read -r -d '' file; do
    [[ -f "$file" ]] || continue
    mkdir -p "$TMPDIR/$(dirname "$file")"
    git show ":$file" > "$TMPDIR/$file" 2>/dev/null || true
  done
  python3 -m keyscan scan --repo "$TMPDIR" -o "$TMPDIR/out" --no-alert --no-entropy >/dev/null 2>&1 || true
  FINDINGS="$TMPDIR/out/report.json"
  if [[ -f "$FINDINGS" ]]; then
    COUNT=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('total_findings',0))" "$FINDINGS")
    if [[ "${{COUNT:-0}}" -gt 0 ]]; then
      echo "COMMIT BLOCKED: $COUNT potential secret(s) in staged changes"
      echo "Review: $TMPDIR/out/report.md"
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
