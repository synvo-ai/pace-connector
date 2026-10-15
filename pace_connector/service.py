"""The trust boundary: email -> masked canonical JSON -> engine HTTP API."""

from __future__ import annotations

import json
import re
from typing import Any, TYPE_CHECKING

from .client import EngineClient
from .contracts import (
    CONNECTOR_CONTRACT_VERSION,
    HTTP_CONTRACT_VERSION,
    AttachmentMetadata,
    ConnectorFailure,
    ConnectorInput,
    ConnectorResult,
)
from .errors import AttachmentLimitError, ConnectorError, MaskingFailureError, RequestLimitError
from .graph import parse_graph_message
from . import names
from .masking import LocalPrivacyMasker, MaskingEngine, MaskingSession
from .mime import parse_rfc5322
from .privacy import EgressPrivacyGate, EgressPrivacySentinel, LocalPrivacyDetector, PrivacyDetector

if TYPE_CHECKING:
    from .attachments import LocalAttachmentProcessor

_MAX_IDENTIFIER_CHARS = 160
_MAX_SUBJECT_CHARS = 1_000
_MAX_BODY_CHARS = 40_000
_MAX_THREAD_BODY_CHARS = 20_000
_MAX_ATTACHMENTS = 24
_MAX_ATTACHMENT_METADATA_CHARS = 1_000
_MAX_THREAD_MESSAGES = 30
_MAX_PRIOR_ISSUES = 24
_MAX_PRIOR_ISSUE_SUMMARY_CHARS = 1_000
_MAX_MISSING_INFORMATION_ITEMS = 12
_MAX_MISSING_INFORMATION_CHARS = 360
_MAX_CANONICAL_JSON_BYTES = 128 * 1024


class MimePrivacyConnector:
    """Stateless service. No spool, mailbox, sender, trace or placeholder store exists here."""

    def __init__(self, engine_client: EngineClient, masking_engine: MaskingEngine | None = None, attachment_processor: "LocalAttachmentProcessor | None" = None, privacy_detector: PrivacyDetector | None = None, egress_gate: EgressPrivacyGate | None = None) -> None:
        self._engine_client = engine_client
        self._privacy_detector = privacy_detector or LocalPrivacyDetector()
        self._masking_engine = masking_engine or LocalPrivacyMasker(self._privacy_detector)
        self._attachment_processor = attachment_processor
        # The final gate deliberately owns an independent sentinel; it must not
        # reuse the masking detector and repeat a correlated miss.
        self._egress_gate = egress_gate or EgressPrivacyGate()

    def process(self, connector_input: ConnectorInput) -> ConnectorResult:
        try:
            canonical, session, known_names = self._build_canonical_request(connector_input)
            # Independent from source masking: inspect precisely what would
            # leave this process before the HTTP client can be called.
            self._egress_gate.validate(canonical, known_names=known_names)
            engine_response = self._engine_client.analyse(canonical)
            return ConnectorResult(
                status="COMPLETED",
                connector_contract_version=CONNECTOR_CONTRACT_VERSION,
                canonical_request=canonical,
                engine_result=engine_response,
                restored_reply=_restore_reply(engine_response, session),
                failure=None,
                restored_result=_restore_result(engine_response, session),
            )
        except ConnectorError as error:
            return ConnectorResult(
                status="REQUIRES_MANUAL_HANDLING",
                connector_contract_version=CONNECTOR_CONTRACT_VERSION,
                canonical_request=None,
                engine_result=None,
                restored_reply=None,
                failure=ConnectorFailure(error.code, error.safe_message),
            )
        except Exception:
            return ConnectorResult(
                status="REQUIRES_MANUAL_HANDLING",
                connector_contract_version=CONNECTOR_CONTRACT_VERSION,
                canonical_request=None,
                engine_result=None,
                restored_reply=None,
                failure=ConnectorFailure("INTERNAL_CONNECTOR_ERROR", "The email could not be prepared safely."),
            )

    def _build_canonical_request(self, connector_input: ConnectorInput) -> tuple[dict[str, Any], MaskingSession, tuple[str, ...]]:
        limits = connector_input.limits
        _validate_identifier(connector_input.request_id, limits, "request")
        _validate_identifier(connector_input.correlation_id, limits, "correlation")
        _validate_identifier(connector_input.idempotency_key, limits, "idempotency")
        if len(connector_input.permitted_thread) > _effective_limit(limits.max_thread_messages, _MAX_THREAD_MESSAGES):
            raise RequestLimitError()
        if len(connector_input.prior_issues) > _effective_limit(limits.max_prior_issues, _MAX_PRIOR_ISSUES):
            raise RequestLimitError()
        _validate_thread(connector_input, limits)
        _validate_prior_issues(connector_input, limits)
        _validate_external_attachments(connector_input, limits)
        if connector_input.graph_message is not None:
            parsed = parse_graph_message(connector_input.graph_message, limits)
        else:
            parsed = parse_rfc5322(connector_input.raw_eml, limits)
        _validate_bounded_text(parsed.subject, _effective_limit(limits.max_subject_chars, _MAX_SUBJECT_CHARS))
        _validate_bounded_text(parsed.current_body, _effective_limit(limits.max_body_chars, _MAX_BODY_CHARS))
        attachments = (*parsed.attachments, *(item.metadata for item in connector_input.local_attachments), *connector_input.externally_observed_attachments)
        if len(attachments) > _effective_limit(limits.max_attachments, _MAX_ATTACHMENTS):
            raise AttachmentLimitError()
        # Same idempotency key -> same placeholders, so a retry replays instead of conflicting.
        known_names = names.known_name_terms((parsed.local_sender, *parsed.local_recipients, *connector_input.thread_addresses))
        if isinstance(self._masking_engine, LocalPrivacyMasker):
            session = self._masking_engine.new_seeded_session(connector_input.idempotency_key, known_names=known_names)
        else:
            session = self._masking_engine.new_session()
        current = {
            "messageId": "current-message",
            "subject": session.mask(parsed.subject).masked_text,
            "body": session.mask(parsed.current_body).masked_text,
        }
        permitted_thread = [
            {"messageId": f"thread-{index:03d}", "direction": item.direction, "body": session.mask(item.body).masked_text}
            for index, item in enumerate(connector_input.permitted_thread, start=1)
        ]
        prior_issues = [
            {
                "issueId": f"prior-{index:03d}",
                "summary": session.mask(item.summary).masked_text,
                **({"missingInformation": [session.mask(value).masked_text for value in item.missing_information]} if item.missing_information else {}),
            }
            for index, item in enumerate(connector_input.prior_issues, start=1)
        ]
        attachment_evidence = self._attachment_evidence(attachments, (*parsed.local_attachments, *connector_input.local_attachments), session)
        canonical = {
            "schemaVersion": HTTP_CONTRACT_VERSION,
            "requestId": connector_input.request_id,
            "correlationId": connector_input.correlation_id,
            "idempotencyKey": connector_input.idempotency_key,
            "dataClassification": "SYNTHETIC_TEST_DATA",
            "enquiry": {
                "currentMessage": current,
                "permittedThread": permitted_thread,
                "priorIssues": prior_issues,
                "attachmentEvidence": attachment_evidence,
            },
        }
        # Masking expands values; validate the actual cloud-bound representation too.
        _validate_bounded_text(current["subject"], _effective_limit(limits.max_subject_chars, _MAX_SUBJECT_CHARS))
        _validate_bounded_text(current["body"], _effective_limit(limits.max_body_chars, _MAX_BODY_CHARS))
        for message in permitted_thread:
            _validate_bounded_text(message["body"], _effective_limit(limits.max_thread_body_chars, _MAX_THREAD_BODY_CHARS))
        for issue in prior_issues:
            _validate_bounded_text(issue["summary"], _effective_limit(limits.max_prior_issue_summary_chars, _MAX_PRIOR_ISSUE_SUMMARY_CHARS))
            for value in issue.get("missingInformation", []):
                _validate_bounded_text(value, _effective_limit(limits.max_missing_information_chars, _MAX_MISSING_INFORMATION_CHARS))
        if len(json.dumps(canonical, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > _effective_limit(limits.max_canonical_json_bytes, _MAX_CANONICAL_JSON_BYTES):
            raise RequestLimitError()
        return canonical, session, known_names

    def _attachment_evidence(self, attachments, local_attachments, session: MaskingSession) -> list[dict[str, Any]]:
        local_by_metadata = {id(item.metadata): item for item in local_attachments}
        evidence: list[dict[str, Any]] = []
        for index, metadata in enumerate(attachments, start=1):
            local = local_by_metadata.get(id(metadata))
            if local is None:
                evidence.append(_attachment_evidence(index, metadata))
                continue
            processor = self._attachment_processor
            if processor is None:
                try:
                    from .attachments import LocalAttachmentProcessor
                    processor = LocalAttachmentProcessor(detector=self._privacy_detector)
                    self._attachment_processor = processor
                except Exception:
                    evidence.append(_attachment_evidence(index, metadata, processing_status="EXTRACTION_FAILED"))
                    continue
            result = processor.process(local)
            if result.status == "PRIVACY_VERIFIED":
                masked = session.mask(result.raw_text_local_only).masked_text
                evidence.append(_attachment_evidence(index, metadata, excerpt=masked or "Attachment content was read locally but contains no text evidence.", extraction_method=result.extraction_method, privacy_transformation=result.privacy_transformation, processing_status=result.status, content_state="METADATA_ONLY"))
            else:
                evidence.append(_attachment_evidence(index, metadata, processing_status=result.status, content_state="NOT_READ"))
        return evidence


def _attachment_evidence(index: int, metadata: AttachmentMetadata, *, excerpt: str | None = None, extraction_method: str = "NONE", privacy_transformation: str = "CONNECTOR_MASKED", processing_status: str = "NOT_READ", content_state: str | None = None) -> dict[str, Any]:
    # No filename, MIME bytes, digest or inferred contents cross the trust boundary.
    return {
        "attachmentId": f"mime-attachment-{index:03d}",
        "pageNumber": None,
        "section": "mime-metadata",
        "excerpt": excerpt or "Attachment metadata was observed; attachment content was not read.",
        "observation": "Connector-local sender document handling only; do not treat attachment content as payment or institutional evidence.",
        "extractionMethod": extraction_method,
        "provider": "python-mime-connector-m2-b",
        "relevance": 0,
        "provenance": "SENDER_PROVIDED",
        "privacyTransformation": privacy_transformation,
        "contentState": content_state or metadata.content_state,
        "processingStatus": processing_status,
    }


_OPAQUE_ID_PREFIXES = {
    "request": "rstn_req_",
    "correlation": "rstn_cor_",
    "idempotency": "rstn_idem_",
}


def _validate_identifier(value: object, limits: Any, kind: str) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > _effective_limit(limits.max_identifier_chars, _MAX_IDENTIFIER_CHARS):
        raise RequestLimitError()
    # Each externally forwarded ID has a distinct connector contract: a fixed
    # machine namespace plus 32 lowercase hexadecimal characters. Human names,
    # prose, separators and caller-chosen payloads cannot cross this boundary.
    prefix = _OPAQUE_ID_PREFIXES.get(kind)
    if prefix is None or not re.fullmatch(rf"{re.escape(prefix)}[0-9a-f]{{32}}", value):
        raise RequestLimitError()
    EgressPrivacySentinel().validate_identifier(value)


def _validate_bounded_text(value: object, maximum: int) -> None:
    if not isinstance(value, str) or len(value) > maximum:
        raise RequestLimitError()


def _validate_thread(connector_input: ConnectorInput, limits: Any) -> None:
    for item in connector_input.permitted_thread:
        if item.direction not in {"USER", "STAFF"}:
            raise RequestLimitError()
        _validate_bounded_text(item.body, _effective_limit(limits.max_thread_body_chars, _MAX_THREAD_BODY_CHARS))


def _validate_prior_issues(connector_input: ConnectorInput, limits: Any) -> None:
    for item in connector_input.prior_issues:
        _validate_bounded_text(item.summary, _effective_limit(limits.max_prior_issue_summary_chars, _MAX_PRIOR_ISSUE_SUMMARY_CHARS))
        if len(item.missing_information) > _effective_limit(limits.max_missing_information_items, _MAX_MISSING_INFORMATION_ITEMS):
            raise RequestLimitError()
        for value in item.missing_information:
            _validate_bounded_text(value, _effective_limit(limits.max_missing_information_chars, _MAX_MISSING_INFORMATION_CHARS))


def _validate_external_attachments(connector_input: ConnectorInput, limits: Any) -> None:
    allowed_states = {"METADATA_ONLY", "NOT_READ", "UNSUPPORTED", "REJECTED_BY_LIMIT"}
    for attachment in connector_input.externally_observed_attachments:
        if not isinstance(attachment, AttachmentMetadata):
            raise AttachmentLimitError()
        values = (attachment.filename or "", attachment.mime_type, attachment.disposition or "")
        if not all(isinstance(value, str) for value in values):
            raise AttachmentLimitError()
        if sum(len(value) for value in values) > _effective_limit(limits.max_attachment_metadata_chars, _MAX_ATTACHMENT_METADATA_CHARS):
            raise AttachmentLimitError()
        if attachment.content_state not in allowed_states:
            raise AttachmentLimitError()
        if attachment.size_bytes is not None and (not isinstance(attachment.size_bytes, int) or attachment.size_bytes < 0):
            raise AttachmentLimitError()


def _effective_limit(configured: object, hard_maximum: int) -> int:
    return min(configured, hard_maximum) if isinstance(configured, int) and configured >= 0 else -1


def _restore_reply(engine_response: dict[str, Any], session: MaskingSession) -> dict[str, str] | None:
    result = engine_response.get("result")
    if not isinstance(result, dict):
        return None
    reply = result.get("reply")
    if not isinstance(reply, dict) or reply.get("status") != "AVAILABLE":
        return None
    subject, body = reply.get("subject"), reply.get("body")
    if not isinstance(subject, str) or not isinstance(body, str):
        return None
    # Only draft text is authorised for local restoration; no telemetry/result fields are restored.
    return {"subject": session.restore(subject), "body": session.restore(body)}


def _restore_result(engine_response: dict[str, Any], session: MaskingSession) -> dict[str, Any] | None:
    result = engine_response.get("result")
    return _restore_strings(result, session) if isinstance(result, dict) else None


def _restore_strings(value: Any, session: MaskingSession) -> Any:
    if isinstance(value, str):
        restored = session.restore(value) if "[[" in value else value
        # A placeholder cut off by truncation ("…[[PII_PER", "…[") cannot be restored; drop it.
        return re.sub(r"\[\[?(?:P(?:I(?:I(?:_[^\]\s]*)?)?)?)?$", "…", restored) if "[" in value[-40:] else restored
    if isinstance(value, list):
        return [_restore_strings(item, session) for item in value]
    if isinstance(value, dict):
        return {key: _restore_strings(item, session) for key, item in value.items()}
    return value
