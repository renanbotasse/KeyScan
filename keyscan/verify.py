"""Live provider checks for compromise verification."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from .aws import AWSSigner
from .constants import DAMAGE_SCOPE, EMAIL_RE
from .models import SecretFinding
from .remediation import RemediationPlanner
from .util import _is_redacted
from .vault import SecretVault


class CompromiseVerifier:
    @staticmethod
    def check_haveibeenpwned_email(email: str, api_key: Optional[str] = None, timeout: int = 5) -> Dict[str, Any]:
        result: Dict[str, Any] = {"checked": False, "breached": False, "detail": ""}
        try:
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}"
            req = urllib.request.Request(url, headers={"User-Agent": "KeyScan/2.0"})
            if api_key:
                req.add_header("hibp-api-key", api_key)
            with urllib.request.urlopen(req, timeout=timeout) as response:
                result.update(checked=True, breached=True, detail="Email found in breach database")
                return result
        except urllib.error.HTTPError as exc:
            result["checked"] = True
            if exc.code == 404:
                result["detail"] = "Email not found in known breaches"
            elif exc.code == 401:
                result["detail"] = "HIBP API key required (set HIBP_API_KEY)"
            else:
                result["detail"] = f"HIBP HTTP {exc.code}"
            return result
        except Exception as exc:  # noqa: BLE001
            result["detail"] = f"HIBP check failed: {exc}"
            return result

    @staticmethod
    def check_pwned_password(password: str, timeout: int = 5) -> Dict[str, Any]:
        """HIBP Pwned Passwords k-anonymity API (no API key)."""
        result: Dict[str, Any] = {"checked": False, "pwned": False, "count": 0, "detail": ""}
        if _is_redacted(password) or len(password) < 4:
            result["detail"] = "Value unsuitable for Pwned Passwords check"
            return result
        try:
            digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
            prefix, suffix = digest[:5], digest[5:]
            req = urllib.request.Request(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"User-Agent": "KeyScan/2.0", "Add-Padding": "true"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
            for line in body.splitlines():
                parts = line.split(":")
                if len(parts) == 2 and parts[0].strip().upper() == suffix:
                    count = int(parts[1].strip())
                    result.update(
                        checked=True,
                        pwned=True,
                        count=count,
                        detail=f"Password appears in breaches ({count} times)",
                    )
                    return result
            result.update(checked=True, pwned=False, detail="Password not found in Pwned Passwords")
            return result
        except Exception as exc:  # noqa: BLE001
            result["detail"] = f"Pwned Passwords check failed: {exc}"
            return result

    @staticmethod
    def check_github_token_active(token: str, timeout: int = 5) -> Dict[str, Any]:
        result: Dict[str, Any] = {"checked": False, "status": "unknown", "detail": "", "scopes": ""}
        if _is_redacted(token) or not token.startswith("gh"):
            result["detail"] = "Not a usable GitHub token value"
            return result
        try:
            req = urllib.request.Request(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"Bearer {token}",
                    "User-Agent": "KeyScan/2.0",
                    "Accept": "application/vnd.github+json",
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as response:
                data = json.loads(response.read().decode())
                scopes = response.headers.get("X-OAuth-Scopes", "")
                login = data.get("login", "?")
                result.update(
                    checked=True,
                    status="active",
                    detail=f"Active as GitHub user '{login}'",
                    scopes=scopes,
                )
                return result
        except urllib.error.HTTPError as exc:
            result.update(
                checked=True,
                status="revoked" if exc.code in (401, 403) else "invalid",
                detail=f"GitHub HTTP {exc.code}",
            )
            return result
        except Exception as exc:  # noqa: BLE001
            result["detail"] = f"GitHub check failed: {exc}"
            return result

    @staticmethod
    def check_stripe_key_active(api_key: str, timeout: int = 5) -> Dict[str, Any]:
        result: Dict[str, Any] = {"checked": False, "status": "unknown", "detail": ""}
        if _is_redacted(api_key) or not api_key.startswith("sk_"):
            result["detail"] = "Not a usable Stripe secret key value"
            return result
        try:
            req = urllib.request.Request("https://api.stripe.com/v1/balance")
            creds = base64.b64encode(f"{api_key}:".encode()).decode()
            req.add_header("Authorization", f"Basic {creds}")
            with urllib.request.urlopen(req, timeout=timeout) as response:
                result.update(checked=True, status="active", detail="Stripe API accepted the key")
                return result
        except urllib.error.HTTPError as exc:
            result.update(
                checked=True,
                status="revoked" if exc.code in (401, 403) else "invalid",
                detail=f"Stripe HTTP {exc.code}",
            )
            return result
        except Exception as exc:  # noqa: BLE001
            result["detail"] = f"Stripe check failed: {exc}"
            return result

    @staticmethod
    def check_slack_token_active(token: str, timeout: int = 5) -> Dict[str, Any]:
        result: Dict[str, Any] = {"checked": False, "status": "unknown", "detail": ""}
        if _is_redacted(token) or not token.startswith("xox"):
            result["detail"] = "Not a usable Slack token"
            return result
        try:
            req = urllib.request.Request(
                "https://slack.com/api/auth.test",
                data=b"",
                headers={"Authorization": f"Bearer {token}"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as response:
                data = json.loads(response.read().decode())
                if data.get("ok"):
                    result.update(
                        checked=True,
                        status="active",
                        detail=f"Slack OK team={data.get('team')} user={data.get('user')}",
                    )
                else:
                    result.update(checked=True, status="invalid", detail=data.get("error", "slack error"))
                return result
        except Exception as exc:  # noqa: BLE001
            result["detail"] = f"Slack check failed: {exc}"
            return result

    @staticmethod
    def check_aws_sts(access_key: str, secret_key: str, region: str = "us-east-1", timeout: int = 10) -> Dict[str, Any]:
        result: Dict[str, Any] = {"checked": False, "status": "unknown", "detail": "", "arn": ""}
        if _is_redacted(access_key) or _is_redacted(secret_key):
            result["detail"] = "Redacted AWS credentials; enable --store-raw to verify"
            return result
        if not re.fullmatch(r"AKIA[0-9A-Z]{16}", access_key):
            result.update(checked=True, status="invalid", detail="Access key format invalid")
            return result
        payload = "Action=GetCallerIdentity&Version=2011-06-15"
        status, body = AWSSigner.request(
            access_key,
            secret_key,
            "POST",
            "https://sts.amazonaws.com/",
            region,
            "sts",
            payload=payload,
            extra_headers={"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
            timeout=timeout,
        )
        result["checked"] = True
        if status == 200 and "Arn" in body:
            arn_m = re.search(r"<Arn>([^<]+)</Arn>", body)
            arn = arn_m.group(1) if arn_m else ""
            result.update(status="active", detail="STS GetCallerIdentity succeeded", arn=arn)
        elif status in (403, 401):
            result.update(status="revoked", detail=f"STS denied HTTP {status}")
        elif status == 0:
            result.update(status="unknown", detail=f"STS network error: {body[:200]}")
        elif "InvalidClientTokenId" in body or "SignatureDoesNotMatch" in body:
            result.update(status="invalid", detail=f"STS rejected credentials HTTP {status}")
        else:
            result.update(status="unknown", detail=f"STS HTTP {status}: {body[:200]}")
        return result

    @staticmethod
    def check_shodan(query: str, api_key: Optional[str] = None, timeout: int = 5) -> Dict[str, Any]:
        result: Dict[str, Any] = {"checked": False, "found": False, "detail": ""}
        if not api_key:
            result["detail"] = "Set SHODAN_API_KEY to enable Shodan checks"
            return result
        try:
            url = "https://api.shodan.io/shodan/host/search?" + urllib.parse.urlencode(
                {"key": api_key, "query": query}
            )
            with urllib.request.urlopen(url, timeout=timeout) as response:
                data = json.loads(response.read().decode())
                total = data.get("total", 0)
                result.update(checked=True, found=total > 0, detail=f"Shodan matches: {total}")
                return result
        except Exception as exc:  # noqa: BLE001
            result["detail"] = f"Shodan check failed: {exc}"
            return result

    @staticmethod
    def check_google_safe_browsing(url: str, api_key: Optional[str] = None, timeout: int = 5) -> Dict[str, Any]:
        result: Dict[str, Any] = {"checked": False, "unsafe": False, "detail": ""}
        if not api_key:
            result["detail"] = "Set GSB_API_KEY to enable Google Safe Browsing checks"
            return result
        try:
            endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find?" + urllib.parse.urlencode(
                {"key": api_key}
            )
            body = json.dumps(
                {
                    "client": {"clientId": "secrets-scanner", "clientVersion": "2.0"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}],
                    },
                }
            ).encode()
            req = urllib.request.Request(endpoint, data=body, method="POST")
            req.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(req, timeout=timeout) as response:
                data = json.loads(response.read().decode() or "{}")
                unsafe = bool(data.get("matches"))
                result.update(checked=True, unsafe=unsafe, detail="Listed" if unsafe else "Not listed")
                return result
        except Exception as exc:  # noqa: BLE001
            result["detail"] = f"GSB check failed: {exc}"
            return result

    @classmethod
    def verify_finding(
        cls,
        finding: SecretFinding,
        raw_value: str = "",
        aws_secret: str = "",
    ) -> SecretFinding:
        value = raw_value or ""
        status, evidence = "unknown", ""

        if finding.secret_type == "GITHUB_TOKEN" and value:
            r = cls.check_github_token_active(value)
            status, evidence = r.get("status", "unknown"), r.get("detail", "")
            if r.get("scopes"):
                evidence += f" scopes={r['scopes']}"
        elif finding.secret_type == "STRIPE_API_KEY" and value:
            r = cls.check_stripe_key_active(value)
            status, evidence = r.get("status", "unknown"), r.get("detail", "")
        elif finding.secret_type == "SLACK_BOT_TOKEN" and value:
            r = cls.check_slack_token_active(value)
            status, evidence = r.get("status", "unknown"), r.get("detail", "")
        elif finding.secret_type == "AWS_ACCESS_KEY":
            if value and aws_secret:
                r = cls.check_aws_sts(value, aws_secret)
                status, evidence = r.get("status", "unknown"), r.get("detail", "")
                if r.get("arn"):
                    evidence += f" arn={r['arn']}"
            elif value and re.fullmatch(r"AKIA[0-9A-Z]{16}", value):
                status, evidence = "format_valid", "Format OK; provide paired secret (vault) for STS check"
            else:
                evidence = "Enable --store-raw on scan for live AWS STS verification"
        elif finding.secret_type in {
            "DATABASE_PASSWORD",
            "ENV_SECRET_VALUE",
            "AWS_SECRET_KEY",
            "API_KEY_GENERIC",
            "HIGH_ENTROPY_STRING",
        } and value:
            r = cls.check_pwned_password(value)
            if r.get("pwned"):
                status, evidence = "pwned", r.get("detail", "")
            elif r.get("checked"):
                status, evidence = "not_pwned", r.get("detail", "")
            else:
                evidence = r.get("detail", "")
        else:
            evidence = "No automated live check for this type (or raw value unavailable); rotate as precaution"

        finding.key_status = status
        finding.is_compromised = status in {"active", "pwned"}
        finding.compromise_evidence = evidence
        finding.damage_scope = finding.damage_scope or DAMAGE_SCOPE.get(finding.secret_type, "")
        finding.remediation = RemediationPlanner.plan_for(finding)
        return finding

    @classmethod
    def verify_all(
        cls,
        findings: List[SecretFinding],
        vault: Optional[SecretVault] = None,
        aws_pairs: Optional[List[Dict[str, str]]] = None,
    ) -> Tuple[List[SecretFinding], Dict[str, Any]]:
        pair_by_access_hash: Dict[str, Dict[str, str]] = {}
        pair_by_file: Dict[str, Dict[str, str]] = {}
        for pair in aws_pairs or []:
            if pair.get("access_hash"):
                pair_by_access_hash[pair["access_hash"]] = pair
            pair_by_file[pair.get("file_path", "")] = pair

        hibp_key = os.environ.get("HIBP_API_KEY")
        shodan_key = os.environ.get("SHODAN_API_KEY")
        gsb_key = os.environ.get("GSB_API_KEY")

        emails = {
            email.lower()
            for f in findings
            for email in EMAIL_RE.findall(f.context or "")
        }
        external: Dict[str, Any] = {
            "emails": [
                {"email": email, **cls.check_haveibeenpwned_email(email, hibp_key)}
                for email in sorted(emails)[:20]
            ],
            "shodan": None,
            "gsb": None,
        }
        if shodan_key and findings:
            external["shodan"] = cls.check_shodan(findings[0].matched_text[:20], shodan_key)
        if gsb_key:
            external["gsb"] = cls.check_google_safe_browsing("https://example.com", gsb_key)

        verified: List[SecretFinding] = []
        for finding in findings:
            raw = vault.get(finding.raw_hash) if vault and finding.raw_hash else ""
            aws_secret = ""
            if finding.secret_type == "AWS_ACCESS_KEY":
                pair = pair_by_access_hash.get(finding.raw_hash) or pair_by_file.get(finding.file_path)
                if pair:
                    aws_secret = pair.get("secret", "")
                    if not raw:
                        raw = pair.get("access", "")
            verified.append(cls.verify_finding(finding, raw_value=raw, aws_secret=aws_secret))
        return verified, external
