"""Versioned local contracts. Raw MIME and local-only envelope fields never enter HTTP JSON."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


CONNECTOR_CONTRACT_VERSION = "pace-mime-connector-v0"
HTTP_CONTRACT_VERSION = "rstn-headless-http-v0"

AttachmentContentState = Literal["METADATA_ONLY", "NOT_READ", "UNSUPPORTED", "REJECTED_BY_LIMIT"]


@dataclass(frozen=True)
class ConnectorLimits:
    max_raw_bytes: int = 256 * 1024
    max_identifier_chars: int = 160
    max_subject_chars: int = 1_000
    max_body_chars: int = 40_000
    max_thread_body_chars: int = 20_000
    max_attachments: int = 24
    max_attachment_metadata_chars: int = 1_000
    max_thread_messages: int = 30
    max_prior_issues: int = 24
    max_prior_issue_summary_chars: int = 1_000
    max_missing_information_items: int = 12
    max_missing_information_chars: int = 360
    max_canonical_json_bytes: int = 128 * 1024


@dataclass(frozen=True)
class ThreadMessage:
    message_id: str
    direction: Literal["USER", "STAFF"]
    body: str


@dataclass(frozen=True)
class PriorIssue:
    issue_id: str
    summary: str
    missing_information: tuple[str, ...] = ()


@dataclass(frozen=True)
class AttachmentMetadata:
    """Local observation only. Its name, content ID and bytes must not cross the API boundary."""

    filename: str | None
    mime_type: str
    size_bytes: int | None
    disposition: str | None
    content_state: AttachmentContentState = "NOT_READ"


@dataclass(frozen=True)
class LocalAttachment:
    """Connector-local attachment bytes. Never serialised into canonical HTTP JSON."""

    metadata: AttachmentMetadata
    content: bytes


@dataclass(frozen=True)
class ConnectorInput:
    """One email: `raw_eml` (RFC 5322 bytes), or `graph_message` (Microsoft Graph message JSON) with `raw_eml=b""`."""

    raw_eml: bytes
    request_id: str
    correlation_id: str
    idempotency_key: str
    opaque_sender_reference: str | None = None
    permitted_thread: tuple[ThreadMessage, ...] = ()
    prior_issues: tuple[PriorIssue, ...] = ()
    externally_observed_attachments: tuple[AttachmentMetadata, ...] = ()
    local_attachments: tuple[LocalAttachment, ...] = ()
    limits: ConnectorLimits = field(default_factory=ConnectorLimits)
    graph_message: bytes | str | dict[str, Any] | None = None


@dataclass(frozen=True)
class ConnectorFailure:
    code: str
    message: str


@dataclass(frozen=True)
class ConnectorResult:
    """A caller-facing result. `canonical_request` is masked and retained only in memory for this call."""

    status: Literal["COMPLETED", "REQUIRES_MANUAL_HANDLING"]
    connector_contract_version: str
    canonical_request: dict[str, Any] | None
    engine_result: dict[str, Any] | None
    restored_reply: dict[str, str] | None
    failure: ConnectorFailure | None
    # The engine result with every placeholder put back (issue summaries, handoff notes, reply).
    # For NTU-side display only; it must never be sent back out.
    restored_result: dict[str, Any] | None = None
