"""Minimal AWS Signature Version 4 signer (stdlib)."""
from __future__ import annotations

import hashlib
import hmac
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple


class AWSSigner:
    """Minimal AWS Signature Version 4 for STS GetCallerIdentity / Secrets Manager."""

    @staticmethod
    def _sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    @classmethod
    def _signature_key(cls, secret_key: str, datestamp: str, region: str, service: str) -> bytes:
        k_date = cls._sign(("AWS4" + secret_key).encode("utf-8"), datestamp)
        k_region = cls._sign(k_date, region)
        k_service = cls._sign(k_region, service)
        return cls._sign(k_service, "aws4_request")

    @classmethod
    def request(
        cls,
        access_key: str,
        secret_key: str,
        method: str,
        url: str,
        region: str,
        service: str,
        payload: str = "",
        extra_headers: Optional[Dict[str, str]] = None,
        timeout: int = 10,
    ) -> Tuple[int, str]:
        parsed = urllib.parse.urlparse(url)
        host = parsed.netloc
        canonical_uri = parsed.path or "/"
        now = datetime.now(timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        datestamp = now.strftime("%Y%m%d")
        payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        headers = {
            "host": host,
            "x-amz-date": amz_date,
            "x-amz-content-sha256": payload_hash,
        }
        if extra_headers:
            headers.update({k.lower(): v for k, v in extra_headers.items()})

        signed_headers = ";".join(sorted(headers.keys()))
        canonical_headers = "".join(f"{k}:{headers[k]}\n" for k in sorted(headers.keys()))
        canonical_querystring = parsed.query
        canonical_request = "\n".join(
            [
                method,
                canonical_uri,
                canonical_querystring,
                canonical_headers,
                signed_headers,
                payload_hash,
            ]
        )
        credential_scope = f"{datestamp}/{region}/{service}/aws4_request"
        string_to_sign = "\n".join(
            [
                "AWS4-HMAC-SHA256",
                amz_date,
                credential_scope,
                hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
            ]
        )
        signing_key = cls._signature_key(secret_key, datestamp, region, service)
        signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        authorization = (
            f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        req_headers = {k: v for k, v in headers.items() if k != "host"}
        req_headers["Authorization"] = authorization
        req_headers["Content-Type"] = (extra_headers or {}).get(
            "Content-Type", "application/x-www-form-urlencoded"
        )

        data = payload.encode("utf-8") if payload else None
        req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            return exc.code, body
        except Exception as exc:  # noqa: BLE001
            return 0, str(exc)
