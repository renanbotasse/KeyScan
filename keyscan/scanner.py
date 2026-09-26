"""Secret scanning across code, env, requirements, Docker, and git history."""
from __future__ import annotations

import re
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .constants import (
    DAMAGE_SCOPE,
    EXTRA_SCAN_NAMES,
    PIP_URL_RE,
    SCAN_EXTENSIONS,
    SKIP_DIRS,
    SKIP_FILES,
    _is_env_file,
)
from .models import SecretFinding, TimelineEntry
from .patterns import SECRET_PATTERNS
from .util import (
    _allowed,
    _env_key_looks_sensitive,
    _fingerprint,
    _is_binary,
    _is_false_positive,
    _load_allowlist,
    _looks_like_secret,
    _redact,
    _sha256,
    _shannon_entropy,
    _unique_rglob,
    _warn,
)
from .vault import SecretVault


class SecretScanner:
    def __init__(self, project_root: str = ".", store_raw: bool = False, vault_path: Optional[Path] = None) -> None:
        self.project_root = Path(project_root).resolve()
        self.patterns = list(SECRET_PATTERNS)
        self.allowlist = _load_allowlist(self.project_root)
        self.store_raw = store_raw
        self.vault = SecretVault(vault_path or (self.project_root / "secrets-report" / ".vault.json"))
        self._aws_pairs: Dict[str, Dict[str, str]] = defaultdict(dict)  # file -> {access, secret}

    def _should_skip(self, path: Path) -> bool:
        if any(part in SKIP_DIRS for part in path.parts):
            return True
        if path.name in SKIP_FILES:
            return True
        if _is_env_file(path.name):
            return True
        if path.suffix in {".yml", ".yaml"} and "workflows" in path.parts and path.name.startswith("secrets-scan"):
            return True
        if path.name in {".secrets-vault.json", ".vault.json", "report.json", "report.md"}:
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
        if _is_false_positive(secret_type, raw, context):
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
            if _is_env_file(name):
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
        """Scan dotenv files. Disabled by default — .env is the expected place for local secrets."""
        findings: List[SecretFinding] = []
        for env_file in _unique_rglob(self.project_root, ".env*"):
            # Still honor explicit include via CLI; _should_skip blocks normal scans
            if env_file.name in SKIP_FILES:
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
                        if key.lower().startswith("export "):
                            key = key[7:].strip()
                        if not value or value.startswith("$") or value.startswith("${"):
                            continue
                        secret_type, severity = None, None
                        for pattern in self.patterns:
                            if pattern.match(value) or pattern.match(line):
                                secret_type, severity = pattern.name, pattern.severity
                                break
                        if secret_type is None:
                            if not _env_key_looks_sensitive(key):
                                continue
                            if len(value) < 12 or not _looks_like_secret(value):
                                if len(value) < 20 or value.lower() in {
                                    "true",
                                    "false",
                                    "none",
                                    "null",
                                }:
                                    continue
                                if re.fullmatch(r"https?://\S+", value) or "@" in value:
                                    continue
                            secret_type, severity = "ENV_SECRET_VALUE", "HIGH"
                        finding = self._make_finding(
                            secret_type, severity, rel, line_num, value, f"{key}=***", ".env"
                        )
                        if finding:
                            finding.matched_text = key  # report key name, not value
                            findings.append(finding)
            except OSError as exc:
                _warn(f"Could not scan {env_file}: {exc}")
        # Also pick up *.env that don't match .env* glob (e.g. foo.env)
        for env_file in _unique_rglob(self.project_root, "*.env"):
            if env_file.name.startswith(".env"):
                continue  # already covered
            if env_file.name in SKIP_FILES:
                continue
            try:
                rel = self._rel(env_file)
                with open(env_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line_num, line in enumerate(f, 1):
                        findings.extend(
                            self._match_line(line, rel, line_num, ".env", entropy_scan=False)
                        )
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
        names = (
            "Dockerfile",
            "Dockerfile.*",
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
        )
        files: List[Path] = []
        for name in names:
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
                        findings.extend(
                            self._match_line(line, rel, line_num, "dockerfile", entropy_scan=True)
                        )
                        if not re.search(
                            r"\b(?:ENV|ARG)\b.+(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE)", line, re.I
                        ):
                            continue
                        m = re.search(r"(?:ENV|ARG)\s+\w+=(.*)$", line)
                        if not m:
                            continue
                        raw = m.group(1).strip().strip("'\"")
                        if not _looks_like_secret(raw):
                            continue
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
