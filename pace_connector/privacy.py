"""Local privacy detection and an independent, fail-closed egress sentinel.

The primary detector locates text to mask. The egress sentinel does not call
that detector: it uses separately normalised structural rules and conservative
residual-person checks. It is a guard against correlated primary misses, not a
claim of multilingual PII coverage.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import json
from pathlib import Path
import re
from typing import Any, Iterable, Literal, Protocol
import unicodedata

from . import details, names
from .errors import EgressPrivacyCheckFailedError, PrivacyDetectorFailureError, PrivacyScopeUnsupportedError

PiiCategory = Literal["EMAIL", "PHONE", "NRIC_FIN", "REFERENCE", "SYNTHETIC_ID", "PERSON", "ADDRESS", "DATE_OF_BIRTH", "ID_NUMBER", "URL", "SECRET"]
# The category kept when findings overlap: the more specific first.
_PRIORITY = {"SYNTHETIC_ID": 0, "EMAIL": 1, "PHONE": 1, "NRIC_FIN": 1, "ID_NUMBER": 2, "REFERENCE": 2, "DATE_OF_BIRTH": 2, "SECRET": 2, "URL": 3, "ADDRESS": 3, "PERSON": 4}


@dataclass(frozen=True)
class PiiFinding:
    category: PiiCategory
    start: int
    end: int
    confidence: float
    detector: str
    masking_policy: Literal["REPLACE"] = "REPLACE"


class PrivacyDetector(Protocol):
    def find(self, text: str) -> tuple[PiiFinding, ...]: ...


_STRUCTURAL_PATTERNS: tuple[tuple[PiiCategory, re.Pattern[str]], ...] = (
    ("EMAIL", re.compile(r"\b[a-z0-9._%+-]+\s*@\s*[a-z0-9-]+(?:\s*\.\s*[a-z0-9-]+)+\b", re.IGNORECASE)),
    # Singapore-style eight-digit values, including qualified 3-series numbers
    # and OCR spacing/hyphen variants.
    ("PHONE", re.compile(r"(?<!\w)(?:\+?\s*65[\s-]*)?[3689](?:[\s-]*[0-9OIl]){7}(?!\w)")),
    ("NRIC_FIN", re.compile(r"\b[STFG]\s*[-]?\s*[0-9OIl](?:\s*[-]?\s*[0-9OIl]){6}\s*[-]?\s*[A-Z]\b", re.IGNORECASE)),
    # Deliberately bounded identifier grammars.  Labels plus prose, dates and
    # amounts are not identifiers merely because they contain a number.
    ("SYNTHETIC_ID", re.compile(r"\bSYN\s*-\s*[A-Z]{2,8}\s*-\s*\d{2,12}\b", re.IGNORECASE)),
    ("REFERENCE", re.compile(r"\b(?:APPLICATION\s*:\s*APP|REFERENCE\s+REF)(?:\s*-\s*|\s+)\w{2,12}(?:\s*-\s*|\s+)\d{2,12}\b", re.IGNORECASE)),
    # Payment, receipt and application codes: capitals, hyphens and a group of 3+ digits
    # (PAY-2026-0042, PACE-GCADA-2026-11903). Programme codes without digits (GC-ADA) and dates stay.
    ("REFERENCE", re.compile(r"\b[A-Z]{2,10}(?:-[A-Z0-9]{1,12})*-\d{3,12}\b")),
    # NTU matriculation numbers (U/N plus seven digits and a letter; the G form is a FIN above).
    ("ID_NUMBER", re.compile(r"\b[UN]\d{7}[A-Z]\b", re.IGNORECASE)),
)
# A value after its label; only the value (group 1) is masked. A student, passport or account number
# needs six or more digits; a password needs a digit or a symbol, so "my password is not working" stays.
_CUED_PATTERNS: tuple[tuple[PiiCategory, re.Pattern[str]], ...] = (
    ("ID_NUMBER", re.compile(r"\b(?:matric(?:ulation)?|student|passport|account|acct)\b(?:\s+(?:no\b\.?|number\b|num\b|id\b|card\b))?(?:\s+[a-z]+){0,2}?\s*(?:\bis\b|\bwas\b|:|#)?\s*([A-Z]{0,2}\d(?:[\d -]{4,22}\d)[A-Z]?)\b", re.IGNORECASE)),
    ("SECRET", re.compile(r"\b(?:password|passcode|passwd|pwd)\b(?:\s+[a-z]+){0,4}?\s*(?:\bis\b|\bwas\b|:|=)\s*[\"“']?([^\s\"”']{4,64}?)[\"”'.,;)]*(?=\s|$)", re.IGNORECASE)),
)
_FIXTURE_PERSON = re.compile(r"\b(?:Alice|Bob|Carol)\s+Example\b")
# This is institutional configuration, not a qualification-fixture allowlist.
# In particular it deliberately contains neither held-out personal names nor
# ordinary business correspondence headings.
_PUBLIC_ENTITY_REGISTRY_PATH = Path(__file__).with_name("public_institutional_entities.v1.json")
_PUBLIC_ENTITY_REGISTRY_SCHEMA_VERSION = "rstn-public-entity-registry-v1"


@dataclass(frozen=True)
class PublicInstitutionalEntityRegistry:
    """Pinned Connector-owned public entities; never accepted from a caller."""

    schema_version: str
    registry_id: str
    registry_version: str
    source_world_digest: str
    entities: tuple[str, ...]


def _normalise_allowlist(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


@lru_cache(maxsize=1)
def public_institutional_entity_registry() -> PublicInstitutionalEntityRegistry:
    """Load and validate the immutable, packaged public-entity snapshot once.

    This adapter intentionally has no request parameter or environment override:
    privacy exemptions are bounded, server/Connector-owned configuration. A
    future approved registry can replace this file and version without changing
    residual-PERSON logic.
    """
    try:
        payload = json.loads(_PUBLIC_ENTITY_REGISTRY_PATH.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("schemaVersion") != _PUBLIC_ENTITY_REGISTRY_SCHEMA_VERSION:
            raise PrivacyDetectorFailureError()
        registry_id, registry_version = payload.get("registryId"), payload.get("registryVersion")
        provenance, records = payload.get("provenance"), payload.get("entities")
        if not isinstance(registry_id, str) or not registry_id or not isinstance(registry_version, str) or not registry_version:
            raise PrivacyDetectorFailureError()
        if not isinstance(provenance, dict) or not isinstance(provenance.get("sourceWorldDigest"), str):
            raise PrivacyDetectorFailureError()
        if not isinstance(records, list) or not records:
            raise PrivacyDetectorFailureError()
        values: set[str] = set()
        for record in records:
            if not isinstance(record, dict) or not isinstance(record.get("controlledId"), str) or not record["controlledId"]:
                raise PrivacyDetectorFailureError()
            names = [record.get("displayName"), *(record.get("aliases") if isinstance(record.get("aliases"), list) else [])]
            if not names or not all(isinstance(name, str) and name.strip() for name in names):
                raise PrivacyDetectorFailureError()
            values.update(_normalise_allowlist(name) for name in names)
        # Single-token aliases (for example an acronym) are harmless but cannot
        # suppress a multi-token residual name because exemptions use exact spans.
        return PublicInstitutionalEntityRegistry(
            _PUBLIC_ENTITY_REGISTRY_SCHEMA_VERSION,
            registry_id,
            registry_version,
            provenance["sourceWorldDigest"],
            tuple(sorted(values, key=lambda value: (-len(value), value))),
        )
    except PrivacyDetectorFailureError:
        raise
    except Exception as error:
        raise PrivacyDetectorFailureError() from error


def public_institutional_entity_registry_provenance() -> dict[str, str]:
    """Safe, non-request provenance for evidence and deployment inspection."""
    registry = public_institutional_entity_registry()
    return {
        "schemaVersion": registry.schema_version,
        "registryId": registry.registry_id,
        "registryVersion": registry.registry_version,
        "sourceWorldDigest": registry.source_world_digest,
    }


def _approved_institutional_entities() -> tuple[str, ...]:
    return public_institutional_entity_registry().entities

# General language policy used by the independent residual sentinel. These are
# single public-domain correspondence concepts, not programme names or fixture
# phrases. Controlled multi-word public entities are handled solely by the
# versioned public-entity adapter above.
_PUBLIC_CORRESPONDENCE_WORDS = frozenset({
    "a", "about", "access", "account", "advanced", "analytics", "allowance", "and", "application", "attached",
    "best", "can", "certificate", "confirmation", "course", "data", "dear", "details",
    "enquiry", "fee", "for", "form", "general", "graduate", "guidance", "help", "in", "information",
    "i", "intake", "may", "office", "payment", "professional", "programme", "receipt",
    "redacted", "reference", "regards", "reply", "schedule", "science", "services", "status",
    "student", "team", "thank", "the", "training", "update", "you", "your",
})
_LOCAL_PLACEHOLDER = re.compile(r"\[\[PII_(?:PERSON|EMAIL|PHONE|NRIC_FIN|REFERENCE|SYNTHETIC_ID|ADDRESS|DATE_OF_BIRTH|ID_NUMBER|URL|SECRET)_[A-Za-z0-9]{8,64}_\d{4}\]\]")
_PERSON_PLACEHOLDER = re.compile(r"\[\[PII_PERSON_[A-Za-z0-9]{8,64}_\d{4}\]\]")


def _assert_english_latin_scope(text: str) -> None:
    """Accept Latin letters/marks; fail closed on every other alphabetic script."""
    for character in text:
        if unicodedata.category(character) == "Nd" and unicodedata.normalize("NFKC", character) not in "0123456789":
            raise PrivacyScopeUnsupportedError()
        if not character.isalpha():
            continue
        if "LATIN" not in unicodedata.name(character, ""):
            raise PrivacyScopeUnsupportedError()


def _normalised_scan(text: str) -> tuple[str, tuple[int, ...]]:
    """NFKC + format removal with normalized-character -> original mapping."""
    output: list[str] = []
    mapping: list[int] = []
    for index, character in enumerate(text):
        if unicodedata.category(character) == "Cf":
            continue
        for normalised in unicodedata.normalize("NFKC", character):
            if unicodedata.category(normalised) == "Cf":
                continue
            output.append(normalised)
            mapping.append(index)
    return "".join(output), tuple(mapping)


def _finding_from_span(start: int, end: int, mapping: tuple[int, ...], original_length: int, detector: str) -> PiiFinding:
    if start >= len(mapping) or end <= start:
        raise PrivacyDetectorFailureError()
    original_start, original_end = mapping[start], mapping[end - 1] + 1
    if not (0 <= original_start < original_end <= original_length):
        raise PrivacyDetectorFailureError()
    return PiiFinding("PERSON", original_start, original_end, 1.0, detector)


def merge_person_findings(findings: Iterable[PiiFinding]) -> list[PiiFinding]:
    """Join overlapping PERSON spans so a partial overlap cannot leave part of a name unmasked."""
    people = sorted((item for item in findings if item.category == "PERSON"), key=lambda item: (item.start, -item.end))
    merged: list[PiiFinding] = []
    for item in people:
        if merged and item.start < merged[-1].end:
            last = merged[-1]
            merged[-1] = PiiFinding("PERSON", last.start, max(last.end, item.end), max(last.confidence, item.confidence), last.detector)
        else:
            merged.append(item)
    return [item for item in findings if item.category != "PERSON"] + merged


def _finding_from_group(category: PiiCategory, match: re.Match[str], mapping: tuple[int, ...], original_length: int, detector: str) -> PiiFinding:
    start, end = match.span(1)
    if start >= len(mapping) or end <= start:
        raise PrivacyDetectorFailureError()
    original_start, original_end = mapping[start], mapping[end - 1] + 1
    if not (0 <= original_start < original_end <= original_length):
        raise PrivacyDetectorFailureError()
    return PiiFinding(category, original_start, original_end, 1.0, detector)


def _finding_from_normalised(category: PiiCategory, match: re.Match[str], mapping: tuple[int, ...], original_length: int, detector: str) -> PiiFinding:
    if match.start() >= len(mapping) or match.end() <= match.start():
        raise PrivacyDetectorFailureError()
    start = mapping[match.start()]
    end = mapping[match.end() - 1] + 1
    if not (0 <= start < end <= original_length):
        raise PrivacyDetectorFailureError()
    return PiiFinding(category, start, end, 1.0, detector)


class SyntheticFixturePrivacyDetector:
    """Deterministic test-only detector retained for isolated fixtures."""

    def find(self, text: str) -> tuple[PiiFinding, ...]:
        if not isinstance(text, str):
            raise PrivacyDetectorFailureError()
        _assert_english_latin_scope(text)
        scanned, mapping = _normalised_scan(text)
        findings = [
            _finding_from_normalised(category, match, mapping, len(text), "synthetic-fixture")
            for category, pattern in _STRUCTURAL_PATTERNS
            if category in {"EMAIL", "PHONE", "SYNTHETIC_ID"}
            for match in pattern.finditer(scanned)
        ]
        findings.extend(_finding_from_normalised("PERSON", match, mapping, len(text), "synthetic-fixture") for match in _FIXTURE_PERSON.finditer(scanned))
        return _deduplicate(findings)


@lru_cache(maxsize=2)
def _load_spacy(model_name: str):
    import spacy
    return spacy.load(model_name, disable=["tagger", "parser", "lemmatizer", "textcat"])


def _value_digits(value: str) -> int:
    return sum(character.isdigit() for character in value)


class LocalPrivacyDetector:
    """Primary detector: structural rules, a pinned local spaCy English NER model for names, and
    the local detail model (`details`) for addresses, dates of birth, numbers, links and secrets.

    `detail_detector`: anything with `spans(text) -> [(start, end, category)]`; by default the
    model in `PACE_DETAIL_MODEL_DIR`. Both models are loaded once per process.
    """

    _structural_patterns = _STRUCTURAL_PATTERNS
    def __init__(self, model_name: str = "en_core_web_trf", detail_detector: Any = None) -> None:
        try:
            self._nlp = _load_spacy(model_name)
            self._details = detail_detector if detail_detector is not None else details.load()
        except PrivacyDetectorFailureError:
            raise
        except Exception as error:
            raise PrivacyDetectorFailureError() from error
        if "ner" not in self._nlp.pipe_names:
            raise PrivacyDetectorFailureError()
        self.model_name = model_name

    def find(self, text: str) -> tuple[PiiFinding, ...]:
        if not isinstance(text, str):
            raise PrivacyDetectorFailureError()
        _assert_english_latin_scope(text)
        try:
            scanned, mapping = _normalised_scan(text)
            findings: list[PiiFinding] = [
                _finding_from_normalised(category, match, mapping, len(text), "primary-structural")
                for category, pattern in self._structural_patterns for match in pattern.finditer(scanned)
            ]
            for match in _FIXTURE_PERSON.finditer(scanned):
                findings.append(_finding_from_normalised("PERSON", match, mapping, len(text), "primary-fixture-person"))
            for category, pattern in _CUED_PATTERNS:
                for match in pattern.finditer(scanned):
                    value = match.group(1)
                    if (category == "ID_NUMBER" and _value_digits(value) < 6) or (category == "SECRET" and value.isalpha() and value.islower()):
                        continue
                    findings.append(_finding_from_group(category, match, mapping, len(text), "primary-cued"))
            findings.extend(PiiFinding(category, start, end, .75, "local-detail-model") for start, end, category in self._details.spans(text))
            approved = _approved_entity_spans(scanned)
            for rule, detector in ((names.title_spans, "primary-title-person"), (names.position_spans, "primary-name-position"), (names.shape_spans, "primary-name-shape")):
                for start, end in rule(scanned):
                    if not _span_is_approved(start, end, approved):
                        findings.append(_finding_from_span(start, end, mapping, len(text), detector))
            document = self._nlp(text)
            for entity in document.ents:
                if entity.label_ != "PERSON" or _is_approved_public_fragment(_normalise_allowlist(entity.text)) or names.is_public_phrase(entity.text):
                    continue
                # A name does not run across a line break ("Li Ting\nFinance Executive").
                start = entity.start_char + len(entity.text) - len(entity.text.lstrip())
                end = start + len(text[start:entity.end_char].split("\n", 1)[0].rstrip())
                # A one-word name that is also an English word ("Mark", "Grace", or "rose" in a lower-case
                # email) is kept: the transformer model rarely tags an ordinary word, and public words are
                # excluded above. The few it does tag ("thanks") are masked; that is safe.
                if len(text[start:end]) < 3:
                    continue
                # spaCy often finds only part of a name ("Ong Hui Shan" of "Camellia Ong Hui Shan").
                start, end = names.extend_span(text, start, end)
                findings.append(PiiFinding("PERSON", start, end, .75, f"spacy-{self.model_name}"))
            people = [(item.start, item.end) for item in merge_person_findings(findings) if item.category == "PERSON"]
            findings.extend(PiiFinding("PERSON", start, end, .75, "primary-repeated-name") for start, end in names.repeated_name_spans(text, people))
            return _deduplicate(merge_person_findings(findings))
        except (PrivacyScopeUnsupportedError, PrivacyDetectorFailureError):
            raise
        except Exception as error:
            raise PrivacyDetectorFailureError() from error


class EgressPrivacySentinel:
    """Independent final check; it never calls the primary detector or spaCy.

    Structural checks use a separately NFKC-normalised, format-character stripped
    representation. PERSON checks use the rules in `names` on the masked text: a name left
    after a title, in a greeting, sign-off, self-introduction or "Name:" field; capitalised
    runs with a non-English word; a capitalised word touching a masked name; the sender's and
    recipients' names from the envelope; and a lower-case two/three-word standalone field.
    Ordinary capitalised phrases ("Applied Data", "Admissions Team", "Do I") do not block.
    """

    def scan_text(self, text: str, *, include_person: bool = True, known_names: tuple[str, ...] = ()) -> bool:
        if not isinstance(text, str):
            raise PrivacyDetectorFailureError()
        _assert_english_latin_scope(text)
        try:
            scanned, _mapping = _normalised_scan(text)
            # Connector placeholders are local opaque markers, not prose or
            # raw PII.  Remove only their complete grammar before residual
            # scanning so their internal all-caps words cannot resemble names.
            had_local_placeholder = _LOCAL_PLACEHOLDER.search(scanned) is not None
            with_placeholders = scanned
            scanned = _LOCAL_PLACEHOLDER.sub(" ", scanned)
            if any(pattern.search(scanned) for _category, pattern in _STRUCTURAL_PATTERNS):
                return True
            if not include_person:
                return False
            if _has_structured_detail(scanned):
                return True
            # Name checks see a placeholder as a non-word mark, so lines and runs stay as written.
            marked = _LOCAL_PLACEHOLDER.sub("\ue001", with_placeholders)
            approved_spans = _approved_entity_spans(marked)
            if _matches_unapproved(_FIXTURE_PERSON, marked, approved_spans):
                return True
            for rule in (names.title_spans, names.position_spans, names.shape_spans):
                if any(not _span_is_approved(start, end, approved_spans) for start, end in rule(marked)):
                    return True
            if names.known_name_spans(marked, known_names):
                return True
            # A capitalised word left touching a masked name is probably the rest of that name.
            for match in _PERSON_PLACEHOLDER.finditer(with_placeholders):
                if names.extend_span(with_placeholders, match.start(), match.end()) != (match.start(), match.end()):
                    return True
            return _has_lowercase_standalone_person(scanned, had_local_placeholder=had_local_placeholder)
        except (PrivacyScopeUnsupportedError, PrivacyDetectorFailureError):
            raise
        except Exception as error:
            raise PrivacyDetectorFailureError() from error

    def validate_identifier(self, value: str) -> None:
        # Machine identifiers are not prose; check structural PII only.
        if self.scan_text(value, include_person=False):
            raise EgressPrivacyCheckFailedError()


class EgressPrivacyGate:
    """Final egress gate backed by `EgressPrivacySentinel`, not the masker."""

    def __init__(self, sentinel: EgressPrivacySentinel | None = None) -> None:
        self._sentinel = sentinel or EgressPrivacySentinel()

    def validate(self, canonical_request: dict[str, Any], known_names: tuple[str, ...] = ()) -> None:
        """`known_names`: the sender's and recipients' names from the envelope (`names.known_name_terms`)."""
        try:
            for path, value in _canonical_string_leaves(canonical_request):
                policy = _EGRESS_STRING_FIELD_POLICY.get(path)
                if policy is None:
                    # A newly added string cannot silently bypass review.
                    raise PrivacyDetectorFailureError()
                if policy == "MACHINE_ID":
                    self._sentinel.validate_identifier(value)
                elif policy == "SAFE_ENUM":
                    if not _is_safe_enum(path, value):
                        raise PrivacyDetectorFailureError()
                elif policy == "CONTENT" and self._sentinel.scan_text(value, known_names=known_names):
                    raise EgressPrivacyCheckFailedError()
        except EgressPrivacyCheckFailedError:
            raise
        except (PrivacyDetectorFailureError, PrivacyScopeUnsupportedError) as error:
            raise EgressPrivacyCheckFailedError() from error


_EGRESS_STRING_FIELD_POLICY: dict[str, Literal["MACHINE_ID", "SAFE_ENUM", "CONTENT"]] = {
    "schemaVersion": "SAFE_ENUM",
    "requestId": "MACHINE_ID", "correlationId": "MACHINE_ID", "idempotencyKey": "MACHINE_ID",
    "dataClassification": "SAFE_ENUM",
    "enquiry.currentMessage.messageId": "SAFE_ENUM",
    "enquiry.currentMessage.subject": "CONTENT", "enquiry.currentMessage.body": "CONTENT",
    "enquiry.permittedThread[].messageId": "SAFE_ENUM", "enquiry.permittedThread[].direction": "SAFE_ENUM", "enquiry.permittedThread[].body": "CONTENT",
    "enquiry.priorIssues[].issueId": "SAFE_ENUM", "enquiry.priorIssues[].summary": "CONTENT", "enquiry.priorIssues[].missingInformation[]": "CONTENT",
    "enquiry.attachmentEvidence[].attachmentId": "SAFE_ENUM", "enquiry.attachmentEvidence[].section": "CONTENT", "enquiry.attachmentEvidence[].excerpt": "CONTENT",
    "enquiry.attachmentEvidence[].observation": "CONTENT", "enquiry.attachmentEvidence[].extractionMethod": "SAFE_ENUM", "enquiry.attachmentEvidence[].provider": "CONTENT",
    "enquiry.attachmentEvidence[].provenance": "SAFE_ENUM", "enquiry.attachmentEvidence[].privacyTransformation": "SAFE_ENUM",
    "enquiry.attachmentEvidence[].contentState": "SAFE_ENUM", "enquiry.attachmentEvidence[].processingStatus": "SAFE_ENUM",
}


def _canonical_string_leaves(value: object, path: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise PrivacyDetectorFailureError()
            yield from _canonical_string_leaves(child, f"{path}.{key}" if path else key)
    elif isinstance(value, list):
        for child in value:
            yield from _canonical_string_leaves(child, f"{path}[]")


def _is_safe_enum(path: str, value: str) -> bool:
    # These fields originate in connector-controlled contract constants.  They
    # remain exact/grammar constrained rather than being treated as free text.
    allowed: dict[str, re.Pattern[str]] = {
        "schemaVersion": re.compile(r"rstn-headless-http-v0"),
        "dataClassification": re.compile(r"SYNTHETIC_TEST_DATA|MASKED"),
        "enquiry.currentMessage.messageId": re.compile(r"current-message"),
        "enquiry.permittedThread[].messageId": re.compile(r"thread-\d{3}"),
        "enquiry.permittedThread[].direction": re.compile(r"USER|STAFF"),
        "enquiry.priorIssues[].issueId": re.compile(r"prior-\d{3}"),
        "enquiry.attachmentEvidence[].attachmentId": re.compile(r"mime-attachment-\d{3}"),
        "enquiry.attachmentEvidence[].extractionMethod": re.compile(r"NONE|OCR|PDF_TEXT"),
        "enquiry.attachmentEvidence[].provenance": re.compile(r"SENDER_PROVIDED"),
        "enquiry.attachmentEvidence[].privacyTransformation": re.compile(r"CONNECTOR_MASKED|CONNECTOR_PIXEL_REDACTED|NONE"),
        "enquiry.attachmentEvidence[].contentState": re.compile(r"METADATA_ONLY|NOT_READ|UNSUPPORTED|REJECTED_BY_LIMIT"),
        "enquiry.attachmentEvidence[].processingStatus": re.compile(r"[A-Z_]{3,64}"),
    }
    pattern = allowed.get(path)
    return pattern is not None and pattern.fullmatch(value) is not None


def _deduplicate(findings: Iterable[PiiFinding]) -> tuple[PiiFinding, ...]:
    """One finding per run of overlapping findings, covering all of them, so a partial overlap cannot
    leave part of a detail readable. It takes the most specific category in the run (`_PRIORITY`),
    and a rule's category over a model's."""
    runs: list[list[PiiFinding]] = []
    run_end = -1
    for finding in sorted(findings, key=lambda item: (item.start, -item.end)):
        if finding.start < 0 or finding.end <= finding.start:
            raise PrivacyDetectorFailureError()
        if runs and finding.start < run_end:
            runs[-1].append(finding)
            run_end = max(run_end, finding.end)
        else:
            runs.append([finding])
            run_end = finding.end
    merged = []
    for run in runs:
        lead = min(run, key=lambda item: (_PRIORITY[item.category], -item.confidence, -(item.end - item.start), item.detector))
        merged.append(PiiFinding(lead.category, run[0].start, max(item.end for item in run), lead.confidence, lead.detector))
    return tuple(merged)


def _is_approved_public_fragment(value: str) -> bool:
    """Keep generic correspondence prose distinct from controlled entities.

    A complete controlled entity is a data-driven exemption. The token-level
    branch remains the pre-existing narrow business-prose handling for a NER
    fragment such as ``Programme Details``; it is not used to enumerate
    programme/service names.
    """
    if value in _approved_institutional_entities():
        return True
    words = value.split()
    return bool(words) and all(word.strip(".'’- ") in _PUBLIC_CORRESPONDENCE_WORDS for word in words)


def _approved_entity_spans(text: str) -> tuple[tuple[int, int], ...]:
    """Return exact approved spans; never rewrite substrings inside a name."""
    return tuple(
        (match.start(), match.end())
        for approved in _approved_institutional_entities()
        for match in re.finditer(rf"(?<!\w){re.escape(approved)}(?!\w)", text, flags=re.IGNORECASE)
    )


def _matches_unapproved(pattern: re.Pattern[str], text: str, approved_spans: tuple[tuple[int, int], ...]) -> bool:
    for match in pattern.finditer(text):
        if not any(start <= match.start() and match.end() <= end for start, end in approved_spans):
            return True
    return False


# Personal details the egress check can recognise without a model, in content fields only.
_EGRESS_DETAIL_PATTERNS = (
    re.compile(r"#\s?\d{1,3}\s?-\s?\d{1,5}\b[^\n]{0,60}?\b\d{6}\b"),  # a unit number followed by a postal code
    re.compile(r"(?<![\w+])\+\s?\d{1,3}[\s-]?\(?\d{1,4}\)?(?:[\s-]?\d{2,6}){2,4}\b"),  # a phone number with a country code
    re.compile(r"(?:date\s+of\s+birth|\bd\.?o\.?b\b|\bborn\b)[^\n\d]{0,20}\d{1,4}[\s./-]+(?:\d{1,2}|[a-z]{3,9})[\s./,-]+\d{2,4}\b", re.IGNORECASE),
)
_POSTAL_CODE = re.compile(r"\b(?:singapore|S)\s*\(?\s*(\d{6})\s*\)?(?!\d)", re.IGNORECASE)
_CARD_NUMBER = re.compile(r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])")


def _luhn(digits: str) -> bool:
    total = 0
    for index, character in enumerate(reversed(digits)):
        value = int(character) * (2 if index % 2 else 1)
        total += value - 9 if value > 9 else value
    return total % 10 == 0


def _has_structured_detail(text: str) -> bool:
    if any(pattern.search(text) for pattern in _EGRESS_DETAIL_PATTERNS):
        return True
    if any(match.group(1) not in details.PUBLIC_POSTAL_CODES for match in _POSTAL_CODE.finditer(text)):
        return True
    return any(_luhn(re.sub(r"\D", "", match.group())) for match in _CARD_NUMBER.finditer(text))


_PERSON_WORD = re.compile(r"[^\W\d_][^\W\d_'’\-]*(?:['’\-][^\W\d_][^\W\d_'’\-]*)*", re.UNICODE)


def _span_is_approved(start: int, end: int, approved_spans: tuple[tuple[int, int], ...]) -> bool:
    return any(approved_start <= start and end <= approved_end for approved_start, approved_end in approved_spans)


def _candidate_is_public_prose(words: tuple[str, ...]) -> bool:
    return all(_normalise_allowlist(word).strip(".'’- ") in _PUBLIC_CORRESPONDENCE_WORDS for word in words)


def _has_lowercase_standalone_person(text: str, *, had_local_placeholder: bool = False) -> bool:
    """A field that is only a lower-case two/three-word name ("ana silva"). Capitalised names are
    covered by `names`; arbitrary lower-case prose is outside scope."""
    standalone = text.strip(" \t\r\n.,;:!?")
    standalone_words = tuple(match.group() for match in _PERSON_WORD.finditer(standalone))
    if not had_local_placeholder and len(standalone_words) in {2, 3} and " ".join(standalone_words) == standalone and not _candidate_is_public_prose(standalone_words):
        return all(word.islower() for word in standalone_words)
    return False
