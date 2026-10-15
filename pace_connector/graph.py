"""Microsoft Graph message JSON -> the same parsed form as an RFC 5322 email.

RSTN reads PaCE mail through Microsoft Graph (`GET /users/{id}/messages/{id}`), so this is
their native input. The body is usually HTML; quoted history sits in a Gmail/Outlook quote
block. Attachments are only present when the caller expands them
(`?$expand=attachments`); `fileAttachment.contentBytes` is base64. Sender, recipients and
Graph IDs stay connector-local, exactly like the headers of an `.eml`.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import json
from typing import Any

from .contracts import AttachmentMetadata, ConnectorLimits, LocalAttachment
from .errors import AttachmentLimitError, BodyUnavailableError, MalformedEmailError, RequestLimitError
from .mime import ParsedMimeMessage, _normalise, _separate_quoted_history

_FILE_ATTACHMENT = "#microsoft.graph.fileAttachment"


@dataclass(frozen=True)
class GraphMessageRefs:
    """Connector-local Graph identifiers, returned to RSTN so it can match the result."""

    message_id: str | None
    internet_message_id: str | None
    conversation_id: str | None


def load_graph_message(data: bytes | str | dict[str, Any], limits: ConnectorLimits) -> dict[str, Any]:
    if isinstance(data, dict):
        return data
    raw = data.encode("utf-8") if isinstance(data, str) else data
    # Base64 attachments make Graph JSON larger than the .eml it came from.
    if not raw or len(raw) > limits.max_raw_bytes * 2:
        raise RequestLimitError()
    try:
        message = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MalformedEmailError() from error
    if not isinstance(message, dict):
        raise MalformedEmailError()
    return message


def graph_refs(message: dict[str, Any]) -> GraphMessageRefs:
    return GraphMessageRefs(_str(message.get("id")), _str(message.get("internetMessageId")), _str(message.get("conversationId")))


def parse_graph_message(data: bytes | str | dict[str, Any], limits: ConnectorLimits) -> ParsedMimeMessage:
    message = load_graph_message(data, limits)
    body = message.get("body")
    if not isinstance(body, dict) or not isinstance(body.get("content"), str):
        raise MalformedEmailError()
    content_type = str(body.get("contentType", "html")).lower()
    if content_type not in {"html", "text"}:
        raise MalformedEmailError()
    if not body["content"].strip():
        raise BodyUnavailableError()
    current, quoted = _separate_quoted_history(_normalise(body["content"], html=content_type == "html"))
    if not current:
        raise BodyUnavailableError()
    subject = _str(message.get("subject")) or ""
    if len(subject) > limits.max_subject_chars or len(current) > limits.max_body_chars:
        raise RequestLimitError()
    attachments, local_attachments = _attachments(message, limits)
    recipients = [_address(item) for key in ("toRecipients", "ccRecipients") for item in (message.get(key) or [])]
    return ParsedMimeMessage(
        subject=subject,
        current_body=current,
        quoted_history=quoted,
        local_sender=_address(message.get("from")) or None,
        local_recipients=tuple(value for value in recipients if value),
        attachments=tuple(attachments),
        local_attachments=tuple(local_attachments),
    )


def _attachments(message: dict[str, Any], limits: ConnectorLimits) -> tuple[list[AttachmentMetadata], list[LocalAttachment]]:
    items = message.get("attachments")
    if items is None:
        # Graph says there are attachments but the caller did not expand them: record that
        # one was seen and not read, so the engine knows the sender sent something.
        if message.get("hasAttachments") is True:
            return [AttachmentMetadata(None, "application/octet-stream", None, "attachment", "NOT_READ")], []
        return [], []
    if not isinstance(items, list):
        raise MalformedEmailError()
    if len(items) > limits.max_attachments:
        raise AttachmentLimitError()
    attachments: list[AttachmentMetadata] = []
    local_attachments: list[LocalAttachment] = []
    for item in items:
        if not isinstance(item, dict):
            raise MalformedEmailError()
        name = _str(item.get("name"))
        mime_type = (_str(item.get("contentType")) or "application/octet-stream").lower()
        disposition = "inline" if item.get("isInline") is True else "attachment"
        size = item.get("size") if isinstance(item.get("size"), int) and item.get("size") >= 0 else None
        if len(name or "") + len(mime_type) + len(disposition) > limits.max_attachment_metadata_chars:
            raise AttachmentLimitError()
        encoded = item.get("contentBytes")
        # itemAttachment (an attached email) and referenceAttachment (a cloud link) are never read.
        if item.get("@odata.type", _FILE_ATTACHMENT) != _FILE_ATTACHMENT or not isinstance(encoded, str):
            attachments.append(AttachmentMetadata(name, mime_type, size, disposition, "UNSUPPORTED"))
            continue
        try:
            content = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as error:
            raise MalformedEmailError() from error
        metadata = AttachmentMetadata(name, mime_type, len(content), disposition, "NOT_READ")
        attachments.append(metadata)
        local_attachments.append(LocalAttachment(metadata, content))
    return attachments, local_attachments


def _address(value: object) -> str:
    if not isinstance(value, dict) or not isinstance(value.get("emailAddress"), dict):
        return ""
    email = value["emailAddress"]
    name, address = _str(email.get("name")) or "", _str(email.get("address")) or ""
    return f"{name} <{address}>" if name and address else name or address


def _str(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None
