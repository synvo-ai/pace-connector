"""Bounded RFC 5322 parsing. Attachment containers are never traversed as message body."""

from __future__ import annotations

from dataclasses import dataclass
from email import policy
from email.message import Message
from email.parser import BytesParser
from html.parser import HTMLParser
import re

from .contracts import AttachmentMetadata, ConnectorLimits, LocalAttachment
from .errors import AttachmentLimitError, BodyUnavailableError, MalformedEmailError, RequestLimitError


@dataclass(frozen=True)
class ParsedMimeMessage:
    subject: str
    current_body: str
    quoted_history: str
    local_sender: str | None
    local_recipients: tuple[str, ...]
    attachments: tuple[AttachmentMetadata, ...]
    local_attachments: tuple[LocalAttachment, ...]


# Marks where quoted history starts in HTML bodies (Gmail and Outlook reply blocks).
_QUOTE_MARK = "\ue000"
_QUOTE_CLASSES = {"gmail_quote", "gmail_quote_container", "yahoo_quoted", "moz-cite-prefix"}
_QUOTE_IDS = {"divrplyfwdmsg", "appendonsend", "mail-editor-reference-message-container"}


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: list[str] = []
        self._skip_depth = 0
        self._quoted = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if not self._quoted and not self._skip_depth and _starts_quote(tag, attrs):
            self._quoted = True
            self._parts.append("\n" + _QUOTE_MARK + "\n")
        if tag in {"script", "style"}:
            self._skip_depth += 1
        elif tag in {"br", "p", "div", "li", "tr"} and not self._skip_depth:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"} and self._skip_depth:
            self._skip_depth -= 1
        elif tag in {"p", "div", "li", "tr"} and not self._skip_depth:
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            self._parts.append(data)

    def text(self) -> str:
        return "".join(self._parts)


def _starts_quote(tag: str, attrs: list[tuple[str, str | None]]) -> bool:
    values = dict(attrs)
    if tag == "blockquote" or (tag == "hr" and values.get("id", "") == "stopSpelling"):
        return True
    classes = set((values.get("class") or "").split())
    return bool(classes & _QUOTE_CLASSES) or (values.get("id") or "").lower() in _QUOTE_IDS


def parse_rfc5322(raw_eml: bytes, limits: ConnectorLimits) -> ParsedMimeMessage:
    if not raw_eml or len(raw_eml) > limits.max_raw_bytes:
        raise RequestLimitError()
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw_eml)
    except (UnicodeError, ValueError, IndexError) as error:
        raise MalformedEmailError() from error
    if message.defects:
        raise MalformedEmailError()

    plain, html, attachments, local_attachments = _collect_parts(message, limits)
    selected = plain if plain.strip() else html
    if not selected or not selected.strip():
        raise BodyUnavailableError()
    normalised = _normalise(selected, html=not plain.strip())
    current, quoted = _separate_quoted_history(normalised)
    if not current:
        raise BodyUnavailableError()
    if len(_header(message, "subject")) > limits.max_subject_chars:
        raise RequestLimitError()
    if len(current) > limits.max_body_chars:
        raise RequestLimitError()
    return ParsedMimeMessage(
        subject=_header(message, "subject"),
        current_body=current,
        quoted_history=quoted,
        local_sender=_header(message, "from") or None,
        local_recipients=tuple(value for value in (_header(message, "to"), _header(message, "cc")) if value),
        attachments=tuple(attachments),
        local_attachments=tuple(local_attachments),
    )


def _collect_parts(message: Message, limits: ConnectorLimits) -> tuple[str, str, list[AttachmentMetadata], list[LocalAttachment]]:
    plain_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[AttachmentMetadata] = []
    local_attachments: list[LocalAttachment] = []

    def visit(part: Message, *, is_root: bool = False) -> None:
        content_type = part.get_content_type().lower()
        if not is_root and _is_attachment_node(part, content_type):
            state = "UNSUPPORTED" if (
                content_type.startswith("application/")
                and part.get_content_disposition() is None
                and part.get_filename() is None
            ) else "NOT_READ"
            _record_attachment(attachments, local_attachments, part, content_type, limits, state)
            return
        if part.is_multipart():
            payload = part.get_payload()
            if not isinstance(payload, list):
                raise MalformedEmailError()
            for child in payload:
                if not isinstance(child, Message):
                    raise MalformedEmailError()
                visit(child)
            return
        if content_type not in {"text/plain", "text/html"}:
            # A filename/disposition is not required: all non-body media is
            # conservative attachment metadata and its bytes remain unread.
            _record_attachment(attachments, local_attachments, part, content_type, limits, "UNSUPPORTED")
            return
        payload = part.get_payload(decode=True) or b""
        if content_type == "text/plain":
            plain_parts.append(_decode_text_part(part, payload))
        elif content_type == "text/html":
            html_parts.append(_decode_text_part(part, payload))

    visit(message, is_root=True)
    return "\n".join(plain_parts), "\n".join(html_parts), attachments, local_attachments


def _is_attachment_node(part: Message, content_type: str) -> bool:
    return (
        part.get_content_disposition() == "attachment"
        or part.get_filename() is not None
        or content_type.startswith(("image/", "audio/", "video/", "application/", "message/"))
    )


def _record_attachment(
    attachments: list[AttachmentMetadata],
    local_attachments: list[LocalAttachment],
    part: Message,
    content_type: str,
    limits: ConnectorLimits,
    content_state: str,
) -> None:
    if len(attachments) >= limits.max_attachments:
        raise AttachmentLimitError()
    filename = part.get_filename()
    disposition = part.get_content_disposition()
    if len((filename or "")) + len(content_type) + len(disposition or "") > limits.max_attachment_metadata_chars:
        raise AttachmentLimitError()
    # Do not decode or inspect attachment payloads merely to compute a size.
    metadata = AttachmentMetadata(filename, content_type, None, disposition, content_state)
    attachments.append(metadata)
    # This is connector-local only; message/rfc822/multipart containers are never traversed.
    payload = part.get_payload(decode=True)
    if payload is not None:
        local_attachments.append(LocalAttachment(metadata, payload))


def _decode_text_part(part: Message, payload: bytes) -> str:
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="strict")
    except (LookupError, UnicodeDecodeError) as error:
        raise BodyUnavailableError() from error


def _normalise(text: str, *, html: bool) -> str:
    text = text.replace(_QUOTE_MARK, "")  # the marker is ours; never trust one in the input
    if html:
        parser = _TextExtractor()
        try:
            parser.feed(text)
            parser.close()
        except ValueError as error:
            raise BodyUnavailableError() from error
        text = parser.text()
    return re.sub(r"\n{3,}", "\n\n", text.replace("\r\n", "\n").replace("\r", "\n")).strip()


def _separate_quoted_history(text: str) -> tuple[str, str]:
    if _QUOTE_MARK in text:
        current, quoted = text.split(_QUOTE_MARK, 1)
        return current.strip(), quoted.replace(_QUOTE_MARK, "").strip()
    lines = text.split("\n")
    boundary = next((index for index, line in enumerate(lines) if re.match(r"^\s*On .+wrote:\s*$", line, re.IGNORECASE)), None)
    if boundary is None:
        # Outlook plain text: "-----Original Message-----" or a "From: ... / Sent: ..." header block.
        boundary = next((index for index, line in enumerate(lines) if re.match(r"^\s*-{2,}\s*Original Message\s*-{2,}\s*$", line, re.IGNORECASE)
                         or (re.match(r"^\s*From:\s+\S", line) and index + 1 < len(lines) and re.match(r"^\s*(Sent|Date):\s+\S", lines[index + 1]))), None)
    if boundary is None:
        boundary = next((index for index, line in enumerate(lines) if line.lstrip().startswith(">")), None)
    if boundary is None:
        return text.strip(), ""
    return "\n".join(lines[:boundary]).strip(), "\n".join(lines[boundary:]).strip()


def _header(message: Message, name: str) -> str:
    value = message.get(name, "")
    return str(value).strip()
