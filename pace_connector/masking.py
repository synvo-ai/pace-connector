"""Request-scoped local placeholders; findings originate from a PrivacyDetector."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import hmac
import os
import re
import secrets
from typing import Protocol

from . import names
from .errors import MaskingFailureError
from .privacy import PiiFinding, PrivacyDetector, _deduplicate, merge_person_findings


@dataclass(frozen=True)
class MaskingResult:
    masked_text: str
    findings: tuple[str, ...]


class MaskingSession(Protocol):
    def mask(self, text: str) -> MaskingResult: ...
    def restore(self, text: str) -> str: ...


class MaskingEngine(Protocol):
    def new_session(self) -> MaskingSession: ...


class SyntheticFixtureMasker:
    """Masks deliberately synthetic test values, not real-world PII.

    A new session has a random nonce, so placeholders cannot collide across
    requests. The raw-to-placeholder map stays inside the session only.
    """

    def new_session(self) -> "SyntheticFixtureMaskingSession":
        return SyntheticFixtureMaskingSession()


class LocalPrivacyMasker:
    """The runtime masker. One detector/session covers every request field.

    `new_seeded_session(idempotency_key)` makes placeholders repeatable for a retry of the same
    email, so the engine sees an identical request and replays its first result instead of
    rejecting a changed one. The nonce is an HMAC under a connector-local secret, so it cannot
    be predicted from the key. Set `PACE_CONNECTOR_NONCE_SECRET` to keep it across restarts.
    """

    def __init__(self, detector: PrivacyDetector, nonce_secret: bytes | None = None) -> None:
        self._detector = detector
        configured = os.environ.get("PACE_CONNECTOR_NONCE_SECRET", "").encode("utf-8")
        self._nonce_secret = nonce_secret or configured or secrets.token_bytes(32)

    def new_session(self, known_names: tuple[str, ...] = ()) -> "LocalPrivacyMaskingSession":
        return LocalPrivacyMaskingSession(self._detector, known_names=known_names)

    def new_seeded_session(self, seed: str, known_names: tuple[str, ...] = ()) -> "LocalPrivacyMaskingSession":
        digest = hmac.new(self._nonce_secret, seed.encode("utf-8"), hashlib.sha256).digest()
        return LocalPrivacyMaskingSession(self._detector, _nonce(digest[:9]), known_names=known_names)


def _nonce(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").replace("-", "A").replace("_", "B")


class LocalPrivacyMaskingSession:
    def __init__(self, detector: PrivacyDetector, nonce: str | None = None, known_names: tuple[str, ...] = ()) -> None:
        self._detector = detector
        self._nonce = nonce or _nonce(secrets.token_bytes(9))
        # The sender's and recipients' own names (`names.known_name_terms`), masked wherever they appear.
        self._known_names = known_names
        self._raw_to_placeholder: dict[str, str] = {}
        self._placeholder_to_raw: dict[str, str] = {}
        self._counts: dict[str, int] = {}

    def mask(self, text: str) -> MaskingResult:
        if not isinstance(text, str):
            raise MaskingFailureError()
        findings = self._detector.find(text)
        if self._known_names:
            extra = [PiiFinding("PERSON", start, end, 1.0, "envelope-name") for start, end in names.known_name_spans(text, self._known_names)]
            findings = _deduplicate(merge_person_findings([*findings, *extra]))
        output = text
        categories: set[str] = set()
        for finding in sorted(findings, key=lambda item: item.start, reverse=True):
            raw = text[finding.start:finding.end]
            if not raw:
                raise MaskingFailureError()
            identity = raw.casefold()
            placeholder = self._raw_to_placeholder.get(identity)
            if placeholder is None:
                sequence = self._counts.get(finding.category, 0) + 1
                self._counts[finding.category] = sequence
                placeholder = f"[[PII_{finding.category}_{self._nonce}_{sequence:04d}]]"
                self._raw_to_placeholder[identity] = placeholder
                self._placeholder_to_raw[placeholder] = raw
            output = output[:finding.start] + placeholder + output[finding.end:]
            categories.add(finding.category)
        return MaskingResult(output, tuple(sorted(categories)))

    def restore(self, text: str) -> str:
        if not isinstance(text, str):
            raise MaskingFailureError()
        output = text
        for placeholder, raw in self._placeholder_to_raw.items():
            output = output.replace(placeholder, raw)
        return output


class SyntheticFixtureMaskingSession:
    _patterns = (
        ("EMAIL", re.compile(r"\b[a-z0-9._%+-]+(?:\.synthetic)?@example\.test\b", re.IGNORECASE)),
        ("PHONE", re.compile(r"\+65\s?\d{4}\s?\d{4}\b")),
        ("PERSON", re.compile(r"\b(?:Alice|Bob|Carol) Example\b")),
        ("IDENTIFIER", re.compile(r"\bSYN-[A-Z0-9-]{4,}\b")),
    )

    def __init__(self) -> None:
        self._nonce = secrets.token_urlsafe(9).replace("-", "A").replace("_", "B")
        self._raw_to_placeholder: dict[str, str] = {}
        self._placeholder_to_raw: dict[str, str] = {}
        self._counts: dict[str, int] = {}

    def mask(self, text: str) -> MaskingResult:
        if not isinstance(text, str):
            raise MaskingFailureError()
        findings: list[str] = []
        output = text
        for kind, pattern in self._patterns:
            def replace(match: re.Match[str]) -> str:
                raw = match.group(0)
                placeholder = self._raw_to_placeholder.get(raw)
                if placeholder is None:
                    sequence = self._counts.get(kind, 0) + 1
                    self._counts[kind] = sequence
                    placeholder = f"[[SYN_{kind}_{self._nonce}_{sequence:04d}]]"
                    self._raw_to_placeholder[raw] = placeholder
                    self._placeholder_to_raw[placeholder] = raw
                findings.append(kind)
                return placeholder
            output = pattern.sub(replace, output)
        return MaskingResult(masked_text=output, findings=tuple(sorted(set(findings))))

    def restore(self, text: str) -> str:
        if not isinstance(text, str):
            raise MaskingFailureError()
        output = text
        for placeholder, raw in self._placeholder_to_raw.items():
            output = output.replace(placeholder, raw)
        return output
