"""Secret detection with severity classification.

Input is JavaScript fetched from the target: attacker-influenced content,
often minified into single lines hundreds of kilobytes long. Every pattern
here is written to be linear-time in the length of the input --

  * no nested quantifiers,
  * no alternation branches that can match the same text,
  * every unbounded-looking quantifier is capped at a length no real
    secret of that shape exceeds,

because a catastrophically-backtracking pattern in a scanner that reads
attacker-controlled text is a denial of service against the scanner
itself, and this project's rules of engagement prohibit ReDoS -- including
against our own tooling. See tests/test_secrets_rules.py for the
adversarial-input benchmark that backs this up with numbers, not just
argument.

Publishable keys (Stripe pk_, Google browser keys) are MEANT to be in
client-side code. Reporting them at high severity is the classic
false-positive flood that buries a real sk_live_ key. They are still
recorded, at info, and a reporting layer can filter them from the default
view.

Two detection strategies are used, deliberately:

  * Vendor-prefix rules (Stripe, AWS, Slack, GitHub, Google) are literal
    enumerations. That is *correct* here, not a shortcut: the prefix is
    the vendor's own contract, and the whole point of distinguishing
    "critical" from "info" (sk_live_ vs pk_live_) depends on matching that
    exact contract. An entropy check cannot tell a Stripe secret key from
    a Stripe publishable key -- they have the same shape and the same
    entropy. Only the literal prefix carries that signal.

  * `generic-high-entropy-token` is a shape/entropy *property* instead of
    a name list, because most real secrets are not from a named vendor --
    they are a client's own API tokens, and no enumeration will ever cover
    those. Its keyword set is deliberately narrower than and non-
    overlapping with generic-api-secret's, so the same text is never
    double-reported under both rules. It is entropy/shape gated because
    its keyword net (`*_key`, `*_token`) is wide enough to also catch
    UUIDs, git SHAs, and MD5/SHA1/SHA256 hex digests sitting next to an
    unrelated variable named merely "key" or "token" -- exactly the kind
    of near-miss real minified JS is full of.

Evidence is truncated to a short prefix/suffix so the report never
reproduces a working credential in full, and the value that feeds
`Finding.id` is a one-way hash of the match, never the raw secret --
consistent with `SecretBundle.__repr__` and the runner's argv redaction
elsewhere in this codebase, which take the same stance: a matched secret
value must never reach a place that gets logged or persisted verbatim.

This module is pure: no subprocess, no network, no file I/O. It is not a
stage and is not registered in app.ALL_STAGES -- Task 6's JS-harvesting
stage is the caller that will hand it text.
"""
from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Callable

from .artifacts import Finding

# ---------------------------------------------------------------------------
# Shape/entropy filter used by the generic-high-entropy-token rule.
# ---------------------------------------------------------------------------

_HEX_HASH_LENGTHS = {32, 40, 64}  # md5, sha1, sha256 hex digest lengths
_HEX_CHARS = set("0123456789abcdefABCDEF")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)


def _shannon_entropy(s: str) -> float:
    """Bits per character. Repetition and small alphabets score low;
    genuinely random tokens score high."""
    if not s:
        return 0.0
    n = len(s)
    counts = Counter(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _char_classes(s: str) -> int:
    """How many of {lower, upper, digit, symbol} appear in s.

    Pure-hex text (git SHAs, MD5/SHA1/SHA256 digests) uses at most two of
    these, even when its raw entropy is fairly high -- hex has a 16-symbol
    alphabet, so it can look "random enough" on entropy alone. Requiring
    at least three classes is what actually separates a real mixed-charset
    credential from a hash.
    """
    classes = 0
    if any(c.islower() for c in s):
        classes += 1
    if any(c.isupper() for c in s):
        classes += 1
    if any(c.isdigit() for c in s):
        classes += 1
    if any(not c.isalnum() for c in s):
        classes += 1
    return classes


def _looks_like_secret(value: str) -> bool:
    """True if `value` has the shape of a real random credential rather
    than a hash, UUID, or other structured near-miss.

    Named individually-excluded shapes (UUID, canonical hash lengths) are
    kept alongside the entropy/charset-class check on purpose: raw hex has
    an entropy ceiling of 4 bits/char, close enough to genuinely random
    mixed-charset text that entropy alone would not reliably separate
    them at these string lengths.
    """
    if _UUID_RE.match(value):
        return False
    if len(value) in _HEX_HASH_LENGTHS and all(c in _HEX_CHARS for c in value):
        return False
    if _char_classes(value) < 3:
        return False
    if _shannon_entropy(value) < 3.5:
        return False
    return True


def _no_filter(_value: str) -> bool:
    return True


@dataclass(frozen=True)
class SecretRule:
    name: str
    pattern: re.Pattern
    severity: str
    title: str
    publishable: bool = False
    remediation: str = "Rotate the credential and move it server-side."
    validate: Callable[[str], bool] = _no_filter


RULES: list[SecretRule] = [
    SecretRule(
        "stripe-secret", re.compile(r"\bsk_live_[0-9a-zA-Z]{16,128}"),
        "critical", "Stripe live secret key in client-side code",
        remediation="Revoke the key in the Stripe dashboard immediately, "
                    "then move all secret-key use server-side.",
    ),
    SecretRule(
        "aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "critical", "AWS access key ID in client-side code",
        remediation="Deactivate the key in IAM and rotate any derived "
                    "credentials.",
    ),
    SecretRule(
        # The OTHER half of an AWS key pair. aws-access-key above matches the
        # ID, which is the half with a self-identifying prefix; the secret has
        # no distinguishing shape at all -- it is 40 characters of base64, the
        # same shape as a hash, an ETag, or a build fingerprint -- so it is
        # matched ONLY next to its own keyword. A bare 40-char-base64 rule
        # would fire constantly on minified JS, which is why the generic rules
        # in this module are entropy-gated and this one is context-gated.
        #
        # `secret_access_key` deliberately does not overlap generic-api-secret's
        # `secret[_-]?key` (that needs "secret_key"/"secretkey" adjacently), so
        # the same text is never double-reported -- see the module docstring.
        #
        # The value is optionally quoted, unlike the JS-shaped rules below
        # which require quotes: this also has to match an unquoted
        # `aws_secret_access_key=...` in a DNS TXT record, which is where a
        # zone transfer finds one. See stages/dnsx.parse_axfr.
        "aws-secret-key",
        re.compile(r"""aws[_-]?secret[_-]?access[_-]?key["']?\s{0,8}[:=]\s{0,8}"""
                   r"""["']?([A-Za-z0-9/+=]{40})\b""", re.I),
        "critical", "AWS secret access key exposed",
        remediation="Deactivate the key pair in IAM immediately and rotate "
                    "any credentials derived from it.",
    ),
    SecretRule(
        "private-key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        "high", "Private key material exposed",
        remediation="Treat the key as compromised; reissue and revoke.",
    ),
    SecretRule(
        "slack-token",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,64}"),
        "high", "Slack token exposed",
        remediation="Revoke the token in the Slack app settings.",
    ),
    SecretRule(
        "github-token",
        re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,255}"),
        "high", "GitHub token exposed",
        remediation="Revoke the token in GitHub developer settings.",
    ),
    SecretRule(
        "generic-api-secret",
        re.compile(r"""["']?(?:api[_-]?secret|client[_-]?secret|"""
                   r"""secret[_-]?key)["']?\s{0,8}[:=]\s{0,8}"""
                   r"""["']([A-Za-z0-9/+_-]{16,128})["']""",
                   re.I),
        "high", "Hardcoded API secret",
    ),
    SecretRule(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,4096}\.[A-Za-z0-9_-]{10,4096}"
                   r"\.[A-Za-z0-9_-]{10,4096}"),
        "low", "JSON Web Token embedded in client-side code",
        remediation="Confirm the token is short-lived and not a service "
                    "credential.",
    ),
    SecretRule(
        "internal-host",
        # Trailing \b matters: without it "cdn.localstatic.example.com"
        # would match on the "local" branch as a prefix of "localstatic".
        re.compile(r"\bhttps?://[a-z0-9.-]{1,120}"
                   r"\.(?:internal|local|intranet|corp)\b(?::\d{1,5})?", re.I),
        "info", "Internal hostname referenced in client-side code",
        remediation="Remove internal references from public bundles.",
    ),
    # ---- publishable: expected to be public, recorded but not alarming ----
    SecretRule(
        "stripe-publishable", re.compile(r"\bpk_live_[0-9a-zA-Z]{16,128}"),
        "info", "Stripe publishable key (expected to be public)",
        publishable=True,
        remediation="No action required; publishable keys are designed for "
                    "client-side use.",
    ),
    SecretRule(
        "google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "info", "Google API key (browser keys are expected to be public)",
        publishable=True,
        remediation="Confirm the key is HTTP-referrer restricted in the "
                    "Google Cloud console.",
    ),
    # ---- property-based: no vendor prefix, gated on shape/entropy ----
    SecretRule(
        "generic-high-entropy-token",
        re.compile(r"""["']?\b(?:api[_-]?key|access[_-]?key|"""
                   r"""auth[_-]?token|access[_-]?token|api[_-]?token)"""
                   r"""["']?\s{0,8}[:=]\s{0,8}"""
                   r"""["']([A-Za-z0-9+/_=-]{20,128})["']""",
                   re.I),
        "medium", "Possible hardcoded credential (heuristic match)",
        remediation="Confirm whether this value is a live credential; if so, "
                    "rotate it and move it server-side.",
        validate=_looks_like_secret,
    ),
]


def _redact(match: str) -> str:
    """Never reproduce a working credential in a report.

    Truncated to a short prefix/suffix plus a length, which is enough for
    a reader to recognise the finding across two runs without ever
    reconstructing the working value from the report.
    """
    if len(match) <= 8:
        return match[:2] + "…"
    return f"{match[:6]}…{match[-2:]} ({len(match)} chars)"


def _fingerprint(raw: str) -> str:
    """One-way identity for a matched value.

    Finding.id is derived from (stage, target, template_id, matcher). Using
    a constant per rule here would make every secret a given rule finds in
    the same source collide into a single finding -- the store keeps only
    the first (ArtifactStore.add_finding uses setdefault), so a second,
    different, real credential would be silently dropped. Hashing the raw
    match keeps identity stable for the *same* secret across runs (so
    re-scans dedupe correctly) while keeping different secrets distinct,
    without ever putting the secret value itself into a persisted field.
    """
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


def scan_text(text: str, source: str, stage: str = "jsrecon") -> list[Finding]:
    """Secrets in `text`, attributed to `source` and reported by `stage`.

    `stage` defaults to jsrecon, which was the only caller when these rules
    were written and is still the main one. It is a parameter because a
    finding's stage is what tells a reader where to go looking, and a
    credential published in a DNS TXT record blamed on the JavaScript stage
    sends them to the wrong evidence file entirely. See stages/dnsx.py, which
    scans zone-transfer TXT with stage="dnsx".
    """
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for rule in RULES:
        for m in rule.pattern.finditer(text):
            raw = m.group(0)
            value = m.group(1) if m.groups() else raw
            if not rule.validate(value):
                continue
            key = (rule.name, raw)
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                stage=stage, severity=rule.severity, title=rule.title,
                target=source, template_id=f"secret-{rule.name}",
                matcher=_fingerprint(raw), evidence=_redact(raw),
                description=(
                    "Publishable credentials are expected in client-side code and "
                    "are recorded for completeness."
                    if rule.publishable else
                    "A credential appears in content served to clients. Anyone who "
                    "loads the page can read it."
                ),
                remediation=rule.remediation,
            ))
    return findings
