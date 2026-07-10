#!/usr/bin/env python3
"""
CloudID-Hunter — High-Performance Cloud Metadata Exposure Discovery Tool v1.3.0

A zero-dependency, concurrent CLI tool for ethical hackers and penetration
testers to discover, audit, and flag exposed cloud metadata fabrics, link-local
configuration leaks, and service tokens from AWS, GCP, Azure, DigitalOcean,
and Kubernetes environments.

Author: HackerAI / Principal Security Engineer
License: Apache 2.0 (Authorized security testing only)
"""

from __future__ import annotations

import argparse
import base64
import binascii
import concurrent.futures
import json
import math
import re
import socket
import ssl
import sys
import time
import typing as t
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# ANSI colour / terminal styling
# ---------------------------------------------------------------------------

class Colours:
    """Terminal ANSI escape codes for structured text output.

    Supports automatic colour stripping when output is not a TTY or when
    the caller explicitly disables colours via the class-level flag.
    """

    _enabled: bool = True

    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    DARK_GREY = "\033[90m"
    BG_RED = "\033[101m"
    BG_YELLOW = "\033[103m"
    BG_GREEN = "\033[102m"
    BG_BLUE = "\033[104m"

    @classmethod
    def _configure(cls, *, no_color: bool = False) -> None:
        """Configure colour output.

        Disables all ANSI codes if:
          - no_color is True (explicit --no-color flag), OR
          - sys.stdout is not a TTY (piped to file or another process)

        Call once at startup before any output is printed.
        """
        if no_color or not sys.stdout.isatty():
            cls._enabled = False
            cls.RESET = ""
            cls.BOLD = ""
            cls.RED = ""
            cls.GREEN = ""
            cls.YELLOW = ""
            cls.BLUE = ""
            cls.MAGENTA = ""
            cls.CYAN = ""
            cls.WHITE = ""
            cls.DARK_GREY = ""
            cls.BG_RED = ""
            cls.BG_YELLOW = ""
            cls.BG_GREEN = ""
            cls.BG_BLUE = ""

    @classmethod
    def severity_colour(cls, severity: str) -> str:
        if not cls._enabled:
            return ""
        severity = severity.upper()
        if severity == "CRITICAL":
            return cls.RED + cls.BOLD
        if severity == "HIGH":
            return cls.RED
        if severity == "MEDIUM":
            return cls.YELLOW
        if severity == "LOW":
            return cls.BLUE
        return cls.WHITE

    @classmethod
    def severity_bg(cls, severity: str) -> str:
        if not cls._enabled:
            return ""
        severity = severity.upper()
        if severity == "CRITICAL":
            return cls.BG_RED
        if severity == "HIGH":
            return cls.BG_RED
        if severity == "MEDIUM":
            return cls.BG_YELLOW
        if severity == "LOW":
            return cls.BG_BLUE
        return cls.RESET


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

class Finding:
    """A single security finding discovered during probing."""

    __slots__ = ("severity", "provider", "endpoint", "description",
                 "raw_snippet", "remediation")

    def __init__(
        self,
        severity: str,
        provider: str,
        endpoint: str,
        description: str,
        raw_snippet: str,
        remediation: str,
    ) -> None:
        self.severity = severity.upper()
        self.provider = provider
        self.endpoint = endpoint
        self.description = description
        self.raw_snippet = raw_snippet
        self.remediation = remediation

    def to_dict(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "provider": self.provider,
            "endpoint": self.endpoint,
            "description": self.description,
            "raw_snippet": self.raw_snippet,
            "remediation": self.remediation,
        }


# ---------------------------------------------------------------------------
# Bounded ReDoS-safe regex patterns
#
# CRITICAL CONTRACT: Every pattern MUST have EXACTLY ONE capturing group
# that wraps the full secret/token value.  re.findall() returns only the
# contents of capturing groups when groups are present, so a single group
# guarantees uniform behaviour across all patterns.
#
# ALL quantifiers are bounded (no {n,}, +, or * on user-captured data) to
# eliminate ReDoS.  The Azure SAS Token pattern specifically uses
# .{0,300}? instead of .*? to strictly cap backtracking depth.
#
# NOTE: There is NO runtime assertion loop validating these patterns.
# Previous attempts at counting parentheses were mathematically flawed
# due to literal parens inside character classes (e.g. Plaintext Secret).
# Every pattern has been manually verified to contain exactly one outer
# capturing group returning a plain string to re.findall().
# ---------------------------------------------------------------------------

PATTERNS: list[tuple[str, str, int, str]] = [
    # AWS Access Key ID (bounded alphanumeric, 20 chars)
    ("AWS Access Key ID",
     r"(?i)(?<![A-Z0-9])((?:AKIA|ASIA)[0-9A-Z]{16})(?![A-Z0-9])",
     3,
     "Exposed AWS Access Key ID — potential IAM credential compromise."),

    # AWS Secret Access Key (40 base64 chars)
    ("AWS Secret Key",
     r"(?i)(?<![a-zA-Z0-9+/=])([a-zA-Z0-9+/]{40})(?![a-zA-Z0-9+/=])",
     3,
     "Exposed AWS Secret Access Key — full IAM credential disclosure."),

    # AWS Session Token (STS)
    # Non-capturing prefix group (?:Fwo...|FQo...) + outer capture group
    # wrapping the entire token string for correct re.findall() extraction.
    ("AWS Session Token",
     r"(?i)((?:FwoGZXIvYXdzE|FQoGZXIvYXdzE)[a-zA-Z0-9+/]{80,200}(?:\={0,2}))(?![a-zA-Z0-9+/=])",
     3,
     "Exposed AWS STS Session Token — temporary credential leak."),

    # GCP Private Key ID (32 hex chars)
    ("GCP Private Key ID",
     r"(?i)private_key_id['\"]?\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?",
     3,
     "Exposed GCP Service Account Private Key ID — potential service account compromise."),

    # GCP OAuth / access token
    ("GCP OAuth Token",
     r"(?i)(ya29\.[a-zA-Z0-9_-]{100,200})",
     3,
     "Exposed GCP OAuth 2.0 access token — valid for GCP API authentication."),

    # Generic JWT (three base64url segments)
    ("JWT Token",
     r"(?i)(?:bearer\s+)?((?:eyJ)[a-zA-Z0-9_-]{10,200}\.[a-zA-Z0-9_-]{10,200}\.[a-zA-Z0-9_-]{10,200})",
     3,
     "Exposed JSON Web Token (JWT) — may grant unauthorized API access."),

    # Azure SAS token signature
    # FIX #2 APPLIED: .{0,300}? replaces .*? — strictly bounded lazy
    # quantifier.  No open-ended quantifier remains in any pattern.
    # Catastrophic backtracking is impossible by construction.
    ("Azure SAS Token",
     r"(?i)(se=20[0-9]{2}-[0-1][0-9]-[0-3][0-9].{0,300}?sig=[a-zA-Z0-9%]{20,100})",
     2,
     "Exposed Azure Shared Access Signature (SAS) token — storage/queue/blob compromise."),

    # Azure Management certificate thumbprint
    ("Azure Cert Thumbprint",
     r"(?i)(?:thumbprint|certificateThumbprint)['\"]?\s*[:=]\s*['\"]?([A-Fa-f0-9]{40})['\"]?",
     2,
     "Exposed Azure management certificate thumbprint."),

    # Generic password / secret lines (bounded guard)
    # NOTE: The character class here contains literal ()[] chars —
    # these are NOT capturing groups, they're literal characters inside
    # a character class [...], and do not affect re.findall() output.
    ("Plaintext Secret",
     r"(?i)(?:password|secret|token|api_key|apikey)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_!@#$%^&*()\-+={}\[\]|;:.<>/?]{8,128})['\"]?",
     1,
     "Potential plaintext secret, password, or API key in metadata."),

    # DigitalOcean API token
    ("DO API Token",
     r"(?i)((?:dop_v1_|do_api_)[a-zA-Z0-9]{40,80})",
     3,
     "Exposed DigitalOcean personal access token — full API compromise."),

    # Kubernetes service account token (mounted in pods)
    ("K8s SA Token",
     r"(?i)([a-zA-Z0-9_-]{20,50}\.[a-zA-Z0-9_-]{20,50}\.[a-zA-Z0-9_-]{20,50})",
     2,
     "Potential Kubernetes service account token — pod-level API server access."),
]


# ---------------------------------------------------------------------------
# Noise reduction / false-positive filtering engine
#
# The regex layer above is intentionally broad (that's what makes it good
# at catching real secrets), which means several patterns will also match
# harmless data: git commit SHAs, container image digests, UUIDs, base64
# blobs of non-secret JSON, doc/example placeholders, etc. This section
# filters matches down before they become findings, without touching the
# detection patterns themselves.
# ---------------------------------------------------------------------------

# Values commonly seen in docs, examples, and test fixtures rather than
# real deployments. Matched case-insensitively against the *whole* token.
_PLACEHOLDER_RE = re.compile(
    r"(?i)^("
    r"x{4,}|0{4,}|1{4,}|9{4,}|"                     # xxxxxxxx / 0000... / 1111...
    r"(?:sample|example|dummy|placeholder|fake|"
    r"changeme|change-me|redacted|your[_-]?"
    r"(?:api)?[_-]?key|foo|bar|lorem|test|"
    r"secret|password|token)[a-z0-9_-]*|"
    r"[a-z0-9_-]*(?:sample|example|dummy|placeholder|"
    r"changeme|redacted)[a-z0-9_-]*"
    r")$"
)

# A run of the same character repeated is never a real secret/token.
_REPEATED_CHAR_RE = re.compile(r"^(.)\1{7,}$")


def _shannon_entropy(s: str) -> float:
    """Return the Shannon entropy (bits/char) of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def _looks_like_placeholder(value: str) -> bool:
    """True if the matched value is a known doc/example/test placeholder."""
    stripped = value.strip().strip("'\"")
    if not stripped:
        return True
    if _PLACEHOLDER_RE.match(stripped):
        return True
    if _REPEATED_CHAR_RE.match(stripped):
        return True
    return False


def _validate_jwt_like_structure(value: str) -> bool:
    """Structurally validate a dot-delimited token as a real JWT.

    A JWT header segment is base64url JSON containing at minimum an "alg"
    key. Random three-segment, dot-separated strings (git refs, image
    digests, version identifiers) will almost never decode to that shape,
    so this eliminates the majority of false positives from the generic
    'K8s SA Token' and 'JWT Token' patterns without weakening the regex.
    """
    parts = value.split(".")
    if len(parts) != 3:
        return False
    header_seg = parts[0]
    padded = header_seg + "=" * (-len(header_seg) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded)
        header = json.loads(decoded)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return False
    if not isinstance(header, dict):
        return False
    return "alg" in header or "typ" in header


# Minimum entropy (bits/char) below which a matched value is treated as
# noise for patterns that capture long, effectively-random secret bodies.
# Real base64/hex secrets sit well above these floors; low-entropy hits
# are almost always padding, repeated bytes, or non-secret boilerplate.
_MIN_ENTROPY_BY_PATTERN: dict[str, float] = {
    "AWS Secret Key": 4.0,
    "GCP OAuth Token": 3.5,
    "DO API Token": 3.0,
    "Plaintext Secret": 2.5,
}

# Patterns whose captured value must additionally pass structural JWT
# validation to count as a finding (see _validate_jwt_like_structure).
_REQUIRES_JWT_STRUCTURE = {"JWT Token", "K8s SA Token"}


# Global toggle, flipped by --no-noise-filter for debugging/tuning runs
# where you want to see everything the raw regexes matched.
_NOISE_FILTER_DISABLED: bool = False


def _is_noise(pattern_name: str, value: str) -> bool:
    """Return True if a regex match should be discarded as a false positive."""
    if _looks_like_placeholder(value):
        return True

    min_entropy = _MIN_ENTROPY_BY_PATTERN.get(pattern_name)
    if min_entropy is not None and _shannon_entropy(value) < min_entropy:
        return True

    if pattern_name in _REQUIRES_JWT_STRUCTURE:
        if not _validate_jwt_like_structure(value):
            return True

    return False


# ---------------------------------------------------------------------------
# Target inventory — metadata endpoints
# ---------------------------------------------------------------------------

class MetadataTarget:
    """Describes a single metadata endpoint to probe."""

    __slots__ = ("provider", "url", "headers", "description", "severity_if_exists")

    def __init__(
        self,
        provider: str,
        url: str,
        headers: dict[str, str] | None,
        description: str,
        severity_if_exists: str = "MEDIUM",
    ) -> None:
        self.provider = provider
        self.url = url
        self.headers = headers or {}
        self.description = description
        self.severity_if_exists = severity_if_exists


def _build_local_targets() -> list[MetadataTarget]:
    """Return the default set of link-local metadata fabric targets."""
    ll = "http://169.254.169.254"

    return [
        # -- AWS IMDSv1 --
        MetadataTarget("AWS", f"{ll}/latest/meta-data/",
                       None, "AWS IMDSv1 metadata root (meta-data)"),
        MetadataTarget("AWS", f"{ll}/latest/meta-data/iam/security-credentials/",
                       None, "AWS IMDSv1 IAM role listing"),
        MetadataTarget("AWS", f"{ll}/latest/user-data",
                       None, "AWS IMDSv1 user-data (custom bootstrap scripts)"),
        MetadataTarget("AWS", f"{ll}/latest/dynamic/instance-identity/document",
                       None, "AWS IMDSv1 instance identity document"),

        # -- GCP --
        MetadataTarget("GCP", f"{ll}/computeMetadata/v1/",
                       {"Metadata-Flavor": "Google"},
                       "GCP metadata root"),
        MetadataTarget("GCP", f"{ll}/computeMetadata/v1/instance/service-accounts/",
                       {"Metadata-Flavor": "Google"},
                       "GCP service account listing"),
        MetadataTarget("GCP",
                       f"{ll}/computeMetadata/v1/instance/service-accounts/default/token",
                       {"Metadata-Flavor": "Google"},
                       "GCP default service account token", "CRITICAL"),
        MetadataTarget("GCP",
                       f"{ll}/computeMetadata/v1/project/attributes/ssh-keys?alt=json",
                       {"Metadata-Flavor": "Google"},
                       "GCP project SSH keys"),
        MetadataTarget("GCP", f"{ll}/computeMetadata/v1/instance/attributes/",
                       {"Metadata-Flavor": "Google"},
                       "GCP instance custom attributes"),
        MetadataTarget("GCP", "http://metadata.google.internal/computeMetadata/v1/",
                       {"Metadata-Flavor": "Google"},
                       "GCP metadata via hostname root"),

        # -- Azure --
        MetadataTarget("Azure",
                       f"{ll}/metadata/instance?api-version=2021-02-01",
                       {"Metadata": "true"},
                       "Azure IMDS instance metadata (all)"),
        MetadataTarget("Azure",
                       f"{ll}/metadata/identity/oauth2/token"
                       "?api-version=2018-02-01&resource=https://management.azure.com/",
                       {"Metadata": "true"},
                       "Azure Managed Identity token", "CRITICAL"),

        # -- DigitalOcean --
        MetadataTarget("DigitalOcean", f"{ll}/metadata/v1/",
                       None, "DigitalOcean metadata root"),
        MetadataTarget("DigitalOcean", f"{ll}/metadata/v1.json",
                       None, "DigitalOcean metadata full JSON"),
        MetadataTarget("DigitalOcean", f"{ll}/metadata/v1/user-data",
                       None, "DigitalOcean user-data"),
        MetadataTarget("DigitalOcean", f"{ll}/metadata/v1/tags",
                       None, "DigitalOcean tags"),

        # -- Kubernetes internal API (in-cluster) --
        MetadataTarget("Kubernetes",
                       "https://kubernetes.default.svc/",
                       None,
                       "K8s in-cluster API server (ClusterIP service)"),
        MetadataTarget("Kubernetes",
                       "https://10.96.0.1:443/",
                       None,
                       "K8s API via default ClusterIP"),

        # -- Kubelet --
        MetadataTarget("Kubelet", "http://127.0.0.1:10250/pods",
                       None, "Kubelet read-only API — pod listing"),
        MetadataTarget("Kubelet", "https://127.0.0.1:10250/pods",
                       None, "Kubelet read-only API (TLS) — pod listing"),
    ]


def _build_external_targets(base_url: str) -> list[MetadataTarget]:
    """Build a target list using a user-supplied external base URL (SSRF proxy)."""
    base = base_url.rstrip("/")

    return [
        MetadataTarget("AWS (proxy)", f"{base}/latest/meta-data/",
                       None, "AWS IMDSv1 root via proxy"),
        MetadataTarget("AWS (proxy)",
                       f"{base}/latest/meta-data/iam/security-credentials/",
                       None, "AWS IMDSv1 IAM roles via proxy"),
        MetadataTarget("AWS (proxy)", f"{base}/latest/user-data",
                       None, "AWS user-data via proxy"),
        MetadataTarget("GCP (proxy)",
                       f"{base}/computeMetadata/v1/instance/service-accounts/default/token",
                       {"Metadata-Flavor": "Google"},
                       "GCP SA token via proxy", "CRITICAL"),
        MetadataTarget("GCP (proxy)", f"{base}/computeMetadata/v1/",
                       {"Metadata-Flavor": "Google"},
                       "GCP metadata root via proxy"),
        MetadataTarget("Azure (proxy)",
                       f"{base}/metadata/instance?api-version=2021-02-01",
                       {"Metadata": "true"},
                       "Azure IMDS via proxy"),
        MetadataTarget("Azure (proxy)",
                       f"{base}/metadata/identity/oauth2/token"
                       "?api-version=2018-02-01&resource=https://management.azure.com/",
                       {"Metadata": "true"},
                       "Azure managed identity token via proxy", "CRITICAL"),
        MetadataTarget("DigitalOcean (proxy)", f"{base}/metadata/v1.json",
                       None, "DO metadata via proxy"),
    ]


# ---------------------------------------------------------------------------
# Shared SSL context (unverified — required for SSRF/internal probing)
# ---------------------------------------------------------------------------

def _make_unverified_ssl_context() -> ssl.SSLContext:
    """Create a permissive SSL context that skips cert verification.

    Required for probing internal metadata endpoints and SSRF proxies
    that present self-signed or non-compliant certificates.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


_UNVERIFIED_CTX = _make_unverified_ssl_context()


# ---------------------------------------------------------------------------
# Network probing engine
#
# EXCEPTION HANDLING NOTE:
# The urllib.request.urlopen() function wraps most low-level socket and SSL
# errors into urllib.error.URLError (which inherits from OSError).  However,
# some edge cases (e.g. ssl.SSLError during handshake outside urlopen's
# internal try/except) can propagate as raw OSError or Exception subclasses.
# The handlers below are ordered from MOST specific to LEAST specific so
# that Python's isinstance() matching catches the right handler.
#
# Hierarchy: HTTPError > URLError > socket.timeout > socket.gaierror >
#            ssl.SSLError > OSError > Exception
# ---------------------------------------------------------------------------

class ProbeResult:
    """Result of probing a single metadata target."""

    __slots__ = ("target", "status_code", "body", "error", "duration_ms",
                 "has_data", "headers")

    def __init__(
        self,
        target: MetadataTarget,
        status_code: int | None = None,
        body: str | None = None,
        error: str | None = None,
        duration_ms: float = 0.0,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.target = target
        self.status_code = status_code
        self.body = body
        self.error = error
        self.duration_ms = duration_ms
        self.has_data = body is not None and len(body) > 0
        # Raw header dict as returned by the server (original casing
        # preserved here; callers should lowercase keys/values themselves
        # when doing case-insensitive comparisons).
        self.headers = headers or {}


def _probe_target(target: MetadataTarget, timeout: float = 4.0) -> ProbeResult:
    """Probe a single metadata endpoint and return the result.

    FIX #3 APPLIED: Every socket-level exception is caught and mapped to
    a clean ProbeResult with a descriptive error string.  No raw traceback
    reaches stderr from this function.
    """
    start = time.perf_counter()
    body: str | None = None
    status: int | None = None
    err: str | None = None
    headers: dict[str, str] = {}

    try:
        req = urllib.request.Request(target.url, method="GET")
        req.add_header("User-Agent",
                       "CloudID-Hunter/1.3 (Security Assessment)")
        req.add_header("Accept", "*/*")

        # Provider-specific headers added via the CORRECT API (.add_header())
        for k, v in target.headers.items():
            req.add_header(k, v)

        with urllib.request.urlopen(
            req, timeout=timeout, context=_UNVERIFIED_CTX
        ) as resp:
            status = resp.status
            headers = dict(resp.headers.items())
            raw = resp.read()
            try:
                body = raw.decode("utf-8", errors="replace")
            except Exception:
                body = raw.decode("latin-1", errors="replace")

    # ---- Specific HTTP errors (has status code and response body) ----
    except urllib.error.HTTPError as exc:
        status = exc.code
        headers = dict(exc.headers.items()) if exc.headers else {}
        try:
            raw = exc.read()
            body = raw.decode("utf-8", errors="replace")
        except Exception:
            body = f"<HTTPError {exc.code}>"

    # ---- URLError: catches DNS failures, connection refused, SSL
    #      handshake errors, timeouts wrapped by urllib internally ----
    except urllib.error.URLError as exc:
        err = f"Host Unreachable: URLError — {exc.reason}"

    # ---- socket.timeout: catches low-level socket timeout before
    #      urllib wraps it (edge case in some Python versions) ----
    except socket.timeout:
        err = "Host Unreachable: socket.timeout — endpoint did not respond"

    # ---- socket.gaierror: catches DNS resolution failures that
    #      bypass urllib's internal handler (rare edge case) ----
    except socket.gaierror as exc:
        err = f"Host Unreachable: DNS/Address error — {exc}"

    # ---- ssl.SSLError: catches SSL negotiation failures that may
    #      propagate outside urllib's internal OSError handler ----
    except ssl.SSLError as exc:
        err = f"Host Unreachable: SSL error — {exc}"

    # ---- Generic OSError: catches ConnectionResetError,
    #      ConnectionRefusedError, ConnectionAbortedError, and any
    #      other OS-level socket anomaly not caught above ----
    except OSError as exc:
        err = f"Host Unreachable: OS error — {exc}"

    # ---- Last-resort catch-all for non-OS-level failures ----
    except Exception as exc:
        err = f"Exception: {exc}"

    elapsed = (time.perf_counter() - start) * 1000.0
    return ProbeResult(
        target=target, status_code=status, body=body,
        error=err, duration_ms=elapsed, headers=headers,
    )


# ====================================================================
# FIX #1 APPLIED: AWS IMDSv2 token retrieval — explicit PUT method
# with independent tight timeout (2.0s max) for the token endpoint.
# ====================================================================
def _probe_aws_imdsv2(ll_base: str = "http://169.254.169.254",
                      global_timeout: float = 4.0) -> ProbeResult | None:
    """Attempt IMDSv2 token acquisition and probe the metadata endpoint.

    Uses a tight inner timeout (2.0s max) for the token PUT so that
    scanning non-AWS environments doesn't stall on the token endpoint.
    """
    # FIX #3: Independent, tighter timeout for token acquisition.
    token_timeout: float = min(global_timeout, 2.0)
    token_url = f"{ll_base}/latest/api/token"

    try:
        # FIX #1: method="PUT" is REQUIRED by AWS IMDSv2 specification.
        # A GET request returns 405 Method Not Allowed.
        token_req = urllib.request.Request(token_url, method="PUT")
        token_req.add_header(
            "X-aws-ec2-metadata-token-ttl-seconds", "21600"
        )
        token_req.add_header(
            "User-Agent", "CloudID-Hunter/1.3 (Security Assessment)"
        )

        with urllib.request.urlopen(
            token_req, timeout=token_timeout, context=_UNVERIFIED_CTX
        ) as resp:
            if resp.status != 200:
                return None
            token = resp.read().decode("utf-8", errors="replace").strip()
            if not token or len(token) < 20:
                return None

    except urllib.error.HTTPError:
        # 403 = IMDSv2 disabled, 405 = PUT not supported
        return None
    except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError):
        # Network unreachable, firewalled, or non-AWS host
        return None

    # Use the acquired token to query metadata
    target = MetadataTarget(
        "AWS (IMDSv2)",
        f"{ll_base}/latest/meta-data/",
        {"X-aws-ec2-metadata-token": token},
        "AWS IMDSv2 metadata root (token-authenticated)",
        severity_if_exists="HIGH",
    )
    return _probe_target(target, timeout=global_timeout)


# ---------------------------------------------------------------------------
# Signature analysis engine
# ---------------------------------------------------------------------------

def _analyze_response(result: ProbeResult) -> list[Finding]:
    """Run signature analysis on a probe result and return findings."""
    findings: list[Finding] = []

    if result.error:
        return findings

    target = result.target
    body = result.body or ""
    status = result.status_code

    # --- Status-code-based findings ---
    if status == 200 and body:
        sev = target.severity_if_exists
        findings.append(Finding(
            severity=sev,
            provider=target.provider,
            endpoint=target.url,
            description=f"{target.description} — accessible (HTTP 200)",
            raw_snippet=body[:500],
            remediation=_remediation_for(target.provider, sev, "data_exposed"),
        ))
    elif status in (401, 403):
        msg = ("endpoint exists but requires authentication"
               if status == 401 else
               "endpoint exists but access forbidden")
        findings.append(Finding(
            severity="MEDIUM",
            provider=target.provider,
            endpoint=target.url,
            description=f"{target.description} — {msg} (HTTP {status})",
            raw_snippet=body[:300] if body else "",
            remediation=_remediation_for(target.provider, "MEDIUM",
                                         "auth_required"),
        ))

    # --- Header-based authenticity gate (proxy targets only) ---
    # External proxy targets (--target) can point at literally any web
    # server. A normal site's 404 page, Cloudflare ray-id cookies, session
    # tokens, etc. are high-entropy and will slip past the noise filters
    # in _is_noise(), getting misreported as exposed cloud credentials.
    # Before running signature regexes against a proxy response, verify
    # the response headers actually look like a real cloud metadata
    # service. If they don't, skip the signature loop entirely — status
    # code / auth findings above are unaffected.
    lower_headers = {
        k.lower(): (v or "").lower() for k, v in result.headers.items()
    }
    is_authentic_cloud = (
        "ec2ws" in lower_headers.get("server", "")
        or "google" in lower_headers.get("metadata-flavor", "")
        or "true" in lower_headers.get("metadata", "")
    )

    if "proxy" in target.provider.lower() and not is_authentic_cloud:
        return findings

    # --- Signature-based findings ---
    # FIX #2: All patterns have exactly one capturing group, so
    # re.findall() returns a list of matched secret strings uniformly.
    if body and len(body) > 4:
        for pattern_name, pattern, severity_rank, description in PATTERNS:
            try:
                matches = re.findall(pattern, body)
            except re.error:
                continue
            if matches:
                # Deduplicate while preserving order
                unique_matches = list(dict.fromkeys(
                    m.strip() for m in matches if m.strip()
                ))
                if not _NOISE_FILTER_DISABLED:
                    unique_matches = [
                        m for m in unique_matches
                        if not _is_noise(pattern_name, m)
                    ]
                if unique_matches:
                    matched_str = ", ".join(unique_matches[:5])
                    if len(unique_matches) > 5:
                        matched_str += (
                            f" ... (+{len(unique_matches) - 5} more)"
                        )
                    severity_map = {3: "CRITICAL", 2: "HIGH", 1: "LOW"}
                    sev = severity_map.get(severity_rank, "MEDIUM")
                    findings.append(Finding(
                        severity=sev,
                        provider=target.provider,
                        endpoint=target.url,
                        description=(
                            f"{description} "
                            f"(matched: {pattern_name}) [{matched_str}]"
                        ),
                        raw_snippet=matched_str[:500],
                        remediation=_remediation_for(target.provider, sev,
                                                     "signature"),
                    ))

    return findings


# ---------------------------------------------------------------------------
# Remediation knowledge base
# ---------------------------------------------------------------------------

def _remediation_for(provider: str, severity: str, kind: str) -> str:
    """Return a concrete, actionable remediation string."""
    provider_lower = provider.lower()

    if "aws" in provider_lower:
        if kind == "data_exposed":
            return (
                "Restrict IMDS access:  1) Enable IMDSv2 with Hop Limit 1 "
                "on instances.  2) Apply IAM least-privilege policies to "
                "instance roles.  3) Use network policies (e.g. iptables) "
                "to block pod access to 169.254.169.254.  4) Rotate any "
                "exposed credentials immediately via AWS IAM."
            )
        if kind == "signature":
            return (
                "Exposed AWS credential detected.  Immediately: "
                "1) Deactivate the IAM access key.  2) Rotate the secret key. "
                "3) Audit CloudTrail for unauthorized use. "
                "4) Apply IMDSv2 + Hop Limit 1 on the instance."
            )
        return (
            "Audit IAM roles and restrict IMDS.  Enable IMDSv2, enforce "
            "Hop Limit 1, and use VPC endpoint policies to limit access."
        )

    if "gcp" in provider_lower or "google" in provider_lower:
        if kind == "data_exposed":
            return (
                "Restrict GCP metadata access:  1) Shielded VMs with "
                "--no-scopes for default SA.  2) Use Workload Identity for "
                "GKE instead of node SA metadata access.  3) Block pod egress "
                "to 169.254.169.254 with Kubernetes NetworkPolicies. "
                "4) Immediately rotate exposed service account keys."
            )
        if kind == "signature":
            return (
                "GCP credential exposed.  Immediately: 1) Revoke the "
                "compromised OAuth token via Google Cloud Console. "
                "2) Rotate the service account key.  3) Audit IAM usage logs. "
                "4) Disable default SA access on GCE instances."
            )
        return (
            "Disable default service account metadata access on GCE instances."
            "  Use Workload Identity for GKE.  Shielded VMs."
        )

    if "azure" in provider_lower:
        if kind == "data_exposed":
            return (
                "Restrict Azure IMDS:  1) Block IMDS traffic from pods with "
                "AKS network policies.  2) Use managed identity with "
                "least-privilege scope.  3) Enable Azure AD authentication "
                "for IMDS queries.  4) Rotate any exposed managed identity "
                "tokens."
            )
        if kind == "signature":
            return (
                "Azure SAS/certificate exposed.  Immediately: "
                "1) Revoke the SAS token (regenerate storage key). "
                "2) Rotate management certificates.  3) Audit Azure activity "
                "logs.  4) Restrict IMDS access via network policies."
            )
        return (
            "Use managed identities with least-privilege.  Block direct IMDS "
            "calls from containers.  Rotate any exposed tokens."
        )

    if "digitalocean" in provider_lower:
        return (
            "Restrict DigitalOcean metadata access:  1) Regenerate any "
            "exposed API tokens in DO Console.  2) Use Droplet firewall "
            "rules to restrict metadata endpoint access.  3) Review user-data "
            "for exposed secrets.  4) Use read-only API tokens where possible."
        )

    if "kubernetes" in provider_lower or "kubelet" in provider_lower:
        return (
            "Kubernetes API/kubelet exposure detected.  Immediately: "
            "1) Apply RBAC least-privilege.  2) Restrict kubelet anonymous "
            "access (--anonymous-auth=false).  3) Use NetworkPolicies to "
            "block egress to metadata IPs.  4) Enable audit logging. "
            "5) Rotate any exposed service account tokens."
        )

    return (
        "Audit the exposed endpoint.  Restrict access using network policies, "
        "authentication enforcement, and least-privilege IAM.  Rotate any "
        "discovered credentials."
    )


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class CloudIDHunter:
    """Main orchestrator for CloudID-Hunter scans."""

    def __init__(
        self,
        targets: list[MetadataTarget],
        timeout: float = 4.0,
        max_workers: int = 20,
        enable_imdsv2: bool = True,
    ) -> None:
        self.targets = targets
        self.timeout = timeout
        self.max_workers = max_workers
        self.enable_imdsv2 = enable_imdsv2
        self.findings: list[Finding] = []
        self.results: list[ProbeResult] = []

    def run(self) -> None:
        """Execute the scan across all targets concurrently."""
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers
        ) as executor:
            future_map: dict[concurrent.futures.Future, MetadataTarget] = {
                executor.submit(_probe_target, t, self.timeout): t
                for t in self.targets
            }
            for future in concurrent.futures.as_completed(future_map):
                target = future_map[future]
                try:
                    result = future.result()
                except Exception as exc:
                    result = ProbeResult(target, error=str(exc))
                self.results.append(result)

        if self.enable_imdsv2:
            imds_result = _probe_aws_imdsv2(
                "http://169.254.169.254", global_timeout=self.timeout,
            )
            if imds_result is not None:
                self.results.append(imds_result)

        for result in self.results:
            self.findings.extend(_analyze_response(result))

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.findings.sort(
            key=lambda f: (
                severity_order.get(f.severity, 99),
                f.provider,
                f.endpoint,
            )
        )

    def has_exposure(self) -> bool:
        """Return True if any findings were discovered."""
        return len(self.findings) > 0


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def _print_text(scanner: CloudIDHunter) -> None:
    """Print findings as a structured, colourised text report.

    ANSI colour codes are automatically stripped when:
      - stdout is not a TTY (piped to file), OR
      - the --no-color flag was passed on the command line.
    """
    H = Colours
    print()
    print(f"{H.BOLD}{H.WHITE}{'═' * 78}{H.RESET}")
    title = "CloudID-Hunter — Cloud Metadata Exposure Report"
    print(f"{H.BOLD}{H.CYAN}{title:^78}{H.RESET}")
    print(f"{H.BOLD}{H.WHITE}{'═' * 78}{H.RESET}")
    total_dur = sum(r.duration_ms for r in scanner.results)
    print(f"  Targets scanned : {len(scanner.targets)} main + 1 IMDSv2 probe")
    print(f"  Findings        : {len(scanner.findings)}")
    print(f"  Duration (approx): {total_dur:.0f} ms total (concurrent)")
    print(f"{H.BOLD}{H.WHITE}{'─' * 78}{H.RESET}")
    print()

    if not scanner.findings:
        print(f"  {H.BOLD}{H.GREEN}"
              f"✓ No exposed metadata or secrets detected.{H.RESET}")
        print(f"  {H.GREEN}"
              f"  The target surfaces appear secure.{H.RESET}")
        print()
        return

    grouped: dict[str, list[Finding]] = {}
    for f in scanner.findings:
        grouped.setdefault(f.severity, []).append(f)

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        findings_list = grouped.get(sev, [])
        if not findings_list:
            continue
        colour = H.severity_colour(sev)
        bg = H.severity_bg(sev)
        label = f" {sev} ({len(findings_list)}) "
        print(f"  {bg}{H.BOLD}{H.WHITE}{label}{H.RESET}")
        print(f"  {H.DARK_GREY}{'─' * 72}{H.RESET}")

        for idx, finding in enumerate(findings_list, 1):
            print(f"  {colour}▶ Finding #{idx}{H.RESET}")
            print(f"    Provider  : {finding.provider}")
            print(f"    Endpoint  : {finding.endpoint}")
            print(f"    Detail    : {finding.description}")
            if finding.raw_snippet:
                snippet = (finding.raw_snippet[:250]
                           .replace("\n", "\\n"))
                print(f"    Evidence  : {H.DARK_GREY}"
                      f"{snippet}{H.RESET}")
            print(f"    {H.BOLD}{H.GREEN}Fix{H.RESET}"
                  f"       : {finding.remediation}")
            print()
        print()

    print(f"{H.BOLD}{H.WHITE}{'═' * 78}{H.RESET}")
    print(f"  {H.BOLD}"
          f"End of report.  Remediate findings by severity.{H.RESET}")
    print(f"{H.BOLD}{H.WHITE}{'═' * 78}{H.RESET}")
    print()


def _print_json(scanner: CloudIDHunter) -> None:
    """Print findings as a JSON object to stdout."""
    output: dict[str, t.Any] = {
        "tool": "CloudID-Hunter",
        "version": "1.3.0",
        "targets_scanned": len(scanner.targets) + 1,
        "total_findings": len(scanner.findings),
        "findings": [f.to_dict() for f in scanner.findings],
    }
    json.dump(output, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="cloudid-hunter",
        description=(
            "CloudID-Hunter — Discover exposed cloud metadata, link-local "
            "configurations, and service tokens in AWS, GCP, Azure, "
            "DigitalOcean, and Kubernetes environments."
        ),
        epilog=(
            "Authorized security testing only.  Pre-verified authorization "
            "required by platform Terms of Service."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-t", "--target",
        type=str,
        default=None,
        metavar="BASE_URL",
        help=(
            "External base URL for SSRF/proxy-based scanning.  When omitted, "
            "the tool probes the local link-local (169.254.169.254) context."
        ),
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="text",
        choices=("text", "json"),
        help="Output format: 'text' (colourised) or 'json' (structured).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=4.0,
        metavar="SECONDS",
        help="HTTP request timeout per endpoint (default: 4.0s).",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=20,
        metavar="N",
        help="Number of concurrent worker threads (default: 20).",
    )
    parser.add_argument(
        "--no-imdsv2",
        action="store_true",
        help="Skip AWS IMDSv2 token-based probing.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colour codes in text output (useful when "
             "piping to files).  Colours are also automatically disabled "
             "when stdout is not a TTY.",
    )
    parser.add_argument(
        "--no-noise-filter",
        action="store_true",
        help="Disable false-positive filtering (placeholder detection, "
             "entropy thresholds, JWT structural validation) and report "
             "every raw regex match. Useful when tuning the patterns "
             "themselves or investigating suspected missed findings.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Main entry point.  Returns Unix exit code (0 = clean)."""
    args = _parse_args(argv)

    # Configure colour output BEFORE any print() call.
    # Handles both explicit --no-color and non-TTY stdout detection.
    Colours._configure(no_color=args.no_color)

    global _NOISE_FILTER_DISABLED
    _NOISE_FILTER_DISABLED = args.no_noise_filter

    if args.target:
        targets = _build_external_targets(args.target)
    else:
        targets = _build_local_targets()

    scanner = CloudIDHunter(
        targets=targets,
        timeout=args.timeout,
        max_workers=args.workers,
        enable_imdsv2=not args.no_imdsv2,
    )
    try:
        scanner.run()
    except KeyboardInterrupt:
        sys.stderr.write("\n[!] Scan interrupted by user.\n")
        return 130

    if args.output == "json":
        _print_json(scanner)
    else:
        _print_text(scanner)

    return 0 if not scanner.has_exposure() else 1


if __name__ == "__main__":
    sys.exit(main())