"""GitHub Actions CI/CD workflow writer."""
from __future__ import annotations

from pathlib import Path


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
        run: python -m keyscan scan-all --repo . -o secrets-report --no-alert --store-raw

      - name: Fail on CRITICAL/HIGH
        run: |
          python <<'PY'
          import json, os, pathlib, sys
          bad, lines = 0, []
          path = pathlib.Path("secrets-report") / "report.json"
          if path.exists():
              for f in json.loads(path.read_text()).get("findings", []):
                  if f.get("severity") in ("CRITICAL", "HIGH"):
                      bad += 1
                      lines.append(f"- [{f['severity']}] {f['secret_type']} in {f['file_path']}")
          pathlib.Path(os.environ["GITHUB_STEP_SUMMARY"]).write_text(
              f"## KeyScan\\nFindings CRITICAL/HIGH: {bad}\\n\\n" + "\\n".join(lines[:50])
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
