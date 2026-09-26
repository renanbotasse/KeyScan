"""Data models for KeyScan findings and patterns."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, Pattern


@dataclass
class SecretPattern:
    name: str
    pattern: str
    severity: str = "HIGH"
    description: str = ""
    regex: Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        flags = re.IGNORECASE if "password" in self.name.lower() else 0
        self.regex = re.compile(self.pattern, flags)

    def match(self, text: str) -> Optional[re.Match[str]]:
        return self.regex.search(text)


@dataclass
class SecretFinding:
    secret_type: str
    severity: str
    file_path: str
    line_number: Optional[int] = None
    matched_text: str = ""  # redacted preview
    context: str = ""
    source: str = "current_code"
    commit_hash: Optional[str] = None
    commit_author: Optional[str] = None
    commit_date: Optional[str] = None
    raw_hash: str = ""  # sha256 of raw secret (safe to store)
    entropy: Optional[float] = None
    is_compromised: bool = False
    compromise_evidence: str = ""
    key_status: str = "unknown"  # active | revoked | invalid | format_valid | unknown | pwned
    damage_scope: str = ""
    remediation: str = ""
    rotation_result: str = ""


@dataclass
class TimelineEntry:
    secret_fingerprint: str
    secret_type: str
    matched_preview: str
    file_path: str
    first_commit: str
    first_author: str
    first_date: str
    last_commit: str
    last_author: str
    last_date: str
    commit_count: int

