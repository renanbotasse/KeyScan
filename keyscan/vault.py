"""Secure vault for raw secret values."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Optional

from .util import _chmod_private, _now_iso, _sha256, _warn


class SecretVault:
    """Stores raw secrets keyed by sha256 hash. File mode 0600."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._data: Dict[str, Dict[str, str]] = {}
        if path.exists():
            try:
                self._data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                _warn(f"Could not load vault {path}: {exc}")
                self._data = {}

    def put(self, raw: str, secret_type: str, file_path: str) -> str:
        h = _sha256(raw)
        self._data[h] = {
            "raw": raw,
            "secret_type": secret_type,
            "file_path": file_path,
            "stored_at": _now_iso(),
        }
        return h

    def get(self, raw_hash: str) -> Optional[str]:
        item = self._data.get(raw_hash)
        return item.get("raw") if item else None

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
        _chmod_private(self.path)
