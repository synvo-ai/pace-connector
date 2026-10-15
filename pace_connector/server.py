"""Local HTTP mode: RSTN's system posts each email here; the connector masks it, calls the
engine and answers with the result, names restored. Runs inside RSTN's network.

    PACE_ENGINE_API_KEY=... python -m pace_connector.server --engine-url https://<engine> --port 8788

POST /v0/messages
    Content-Type: application/json     one Microsoft Graph message (as returned by
                                       GET /users/{id}/messages/{id}, optionally ?$expand=attachments),
                                       or an envelope for a follow-up:
                                       {"message": <Graph message>, "thread": [...], "priorIssues": [...]}
    Content-Type: message/rfc822       one raw .eml
GET  /v0/health

Every outcome of processing an email is HTTP 200 with `status` COMPLETED or
REQUIRES_MANUAL_HANDLING. Non-200 is only for the HTTP call itself (400, 401, 404, 413, 415).
"""

from __future__ import annotations

import argparse
import base64
import binascii
from dataclasses import asdict
from email import policy
from email.parser import BytesParser
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from typing import Any

from .client import LocalHttpEngineClient
from .contracts import CONNECTOR_CONTRACT_VERSION, ConnectorInput, ConnectorLimits, PriorIssue, ThreadMessage
from .errors import ConnectorError
from .graph import graph_refs, load_graph_message, parse_graph_message
from .mime import parse_rfc5322
from .service import MimePrivacyConnector

SERVER_SCHEMA_VERSION = "pace-connector-http-v0"
_MAX_BODY_BYTES = ConnectorLimits().max_raw_bytes * 2


def message_ids(identity: str) -> dict[str, str]:
    """The three engine IDs, derived from the message so a resend of the same email is
    byte-identical and the engine replays its first answer instead of running again."""
    digest = lambda kind: hashlib.sha256(f"{kind}:{identity}".encode("utf-8")).hexdigest()[:32]
    return {"request_id": "rstn_req_" + digest("req"), "correlation_id": "rstn_cor_" + digest("cor"), "idempotency_key": "rstn_idem_" + digest("idem")}


class EnvelopeError(ValueError):
    """The request is not a valid envelope: an integration error, answered with HTTP 400."""


_THREAD_KEEP = 30           # the engine accepts at most 30 earlier messages: the newest are kept
_THREAD_BODY_CHARS = 20_000  # and at most 20,000 characters of each
_PRIOR_ISSUES_KEEP = 24


def build_input(body: bytes, content_type: str, mailbox: frozenset[str] = frozenset()) -> tuple[ConnectorInput, dict[str, str | None]]:
    """`mailbox`: PaCE's own addresses, used to tell STAFF from USER in a thread without `direction`."""
    limits = ConnectorLimits()
    if content_type == "message/rfc822":
        return _eml_input(body, limits, (), ())
    try:
        message: Any = load_graph_message(body, limits)
    except ConnectorError:
        message = body  # the connector reports it as malformed
    if isinstance(message, dict) and ("message" in message or "eml" in message) and "body" not in message:
        return _envelope_input(message, limits, mailbox)
    return _graph_input(message, body, limits, (), (), ())


def _graph_input(message: Any, raw: bytes, limits: ConnectorLimits, thread, prior, addresses, context: str = "") -> tuple[ConnectorInput, dict[str, str | None]]:
    refs = graph_refs(message) if isinstance(message, dict) else None
    key = (refs and (refs.message_id or refs.internet_message_id)) or hashlib.sha256(raw).hexdigest()
    echo = {"id": refs.message_id, "internetMessageId": refs.internet_message_id, "conversationId": refs.conversation_id} if refs else {}
    return ConnectorInput(b"", **message_ids("graph:" + key + context), limits=limits, graph_message=message,
                          permitted_thread=thread, prior_issues=prior, thread_addresses=addresses), echo


def _eml_input(raw: bytes, limits: ConnectorLimits, thread, prior, addresses=(), context: str = "") -> tuple[ConnectorInput, dict[str, str | None]]:
    try:
        message_id = str(BytesParser(policy=policy.default).parsebytes(raw, headersonly=True).get("message-id", "")).strip()
    except Exception:
        message_id = ""
    key = "eml:" + (message_id or hashlib.sha256(raw).hexdigest())
    return ConnectorInput(raw, **message_ids(key + context), limits=limits, permitted_thread=thread, prior_issues=prior, thread_addresses=addresses), {}


def _envelope_input(envelope: dict[str, Any], limits: ConnectorLimits, mailbox: frozenset[str]) -> tuple[ConnectorInput, dict[str, str | None]]:
    unknown = set(envelope) - {"message", "eml", "thread", "priorIssues"}
    if unknown:
        raise EnvelopeError(f"unknown envelope fields: {', '.join(sorted(unknown))}")
    if ("message" in envelope) == ("eml" in envelope):
        raise EnvelopeError("give exactly one of message (Graph JSON) or eml (base64)")
    thread_items = envelope.get("thread", [])
    issues = envelope.get("priorIssues", [])
    if not isinstance(thread_items, list) or not isinstance(issues, list):
        raise EnvelopeError("thread and priorIssues must be arrays")
    thread: list[ThreadMessage] = []
    addresses: list[str] = []
    for index, item in enumerate(thread_items[-_THREAD_KEEP:], start=1):
        body, direction, item_addresses = _thread_item(item, limits, mailbox)
        thread.append(ThreadMessage(f"thread-{index:03d}", direction, body[:_THREAD_BODY_CHARS]))
        addresses.extend(item_addresses)
    prior: list[PriorIssue] = []
    for issue in issues[-_PRIOR_ISSUES_KEEP:]:
        if not isinstance(issue, dict) or not isinstance(issue.get("summary"), str) or not issue["summary"].strip():
            raise EnvelopeError("each prior issue needs a non-empty summary")
        missing = issue.get("missingInformation") or []
        if not isinstance(missing, list) or not all(isinstance(value, str) for value in missing):
            raise EnvelopeError("missingInformation must be an array of strings")
        prior.append(PriorIssue(f"prior-{len(prior) + 1:03d}", issue["summary"].strip()[:1000], tuple(value.strip()[:360] for value in missing if value.strip())[:12]))
    # The context is part of the ID: the same email with a different thread is a new request,
    # while an identical resend replays.
    context = "" if not (thread or prior) else ":ctx:" + hashlib.sha256(json.dumps(
        [[item.direction, item.body] for item in thread] + [[issue.summary, list(issue.missing_information)] for issue in prior], ensure_ascii=False).encode("utf-8")).hexdigest()
    if "eml" in envelope:
        return _eml_input(_base64(envelope["eml"]), limits, tuple(thread), tuple(prior), tuple(addresses), context)
    message = envelope["message"]
    if not isinstance(message, dict):
        raise EnvelopeError("message must be a Graph message object")
    return _graph_input(message, json.dumps(message, sort_keys=True).encode("utf-8"), limits, tuple(thread), tuple(prior), tuple(addresses), context)


def _thread_item(item: Any, limits: ConnectorLimits, mailbox: frozenset[str]) -> tuple[str, str, list[str]]:
    """One earlier message: {"direction"?, "message": Graph} | {"direction"?, "eml": base64} | {"direction", "body": text}."""
    if not isinstance(item, dict) or len({"message", "eml", "body"} & set(item)) != 1:
        raise EnvelopeError("each thread item needs exactly one of message, eml or body")
    direction = item.get("direction")
    if direction is not None and direction not in {"USER", "STAFF"}:
        raise EnvelopeError("thread direction must be USER or STAFF")
    if "body" in item:
        if not isinstance(item["body"], str) or direction is None:
            raise EnvelopeError("a text thread item needs body and direction")
        return item["body"], direction, []
    try:
        parsed = parse_graph_message(item["message"], limits) if "message" in item else parse_rfc5322(_base64(item["eml"]), limits)
    except ConnectorError as error:
        raise EnvelopeError(f"a thread message could not be read ({error.code})") from error
    sender = (parsed.local_sender or "")
    if direction is None:
        if not mailbox:
            raise EnvelopeError("thread direction is missing; send it, or start the connector with --mailbox")
        address = sender.rsplit("<", 1)[-1].rstrip(">").strip().lower()
        direction = "STAFF" if address in mailbox else "USER"
    # Only the message's own new text; its quote repeats older messages already in the thread.
    return parsed.current_body, direction, [sender, *parsed.local_recipients]


def _base64(value: Any) -> bytes:
    if not isinstance(value, str):
        raise EnvelopeError("eml must be a base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise EnvelopeError("eml is not valid base64") from error


class ConnectorHandler(BaseHTTPRequestHandler):
    connector: MimePrivacyConnector
    api_key: str | None = None
    show_masked = False
    mailbox: frozenset[str] = frozenset()
    server_version = "pace-connector"
    sys_version = ""

    def do_GET(self) -> None:
        if self.path.split("?")[0] != "/v0/health":
            return self._send(404, {"error": {"code": "NOT_FOUND"}})
        self._send(200, {"status": "ok", "schemaVersion": SERVER_SCHEMA_VERSION, "connectorContractVersion": CONNECTOR_CONTRACT_VERSION})

    def do_POST(self) -> None:
        if self.path.split("?")[0] != "/v0/messages":
            return self._send(404, {"error": {"code": "NOT_FOUND"}})
        if self.api_key and not hmac.compare_digest(self.headers.get("x-api-key", ""), self.api_key):
            return self._send(401, {"error": {"code": "AUTHENTICATION_REQUIRED"}})
        content_type = (self.headers.get("content-type") or "").split(";")[0].strip().lower()
        if content_type not in {"application/json", "message/rfc822"}:
            return self._send(415, {"error": {"code": "UNSUPPORTED_MEDIA_TYPE", "message": "Send a Graph message as application/json or an .eml as message/rfc822."}})
        length = int(self.headers.get("content-length") or 0)
        if length <= 0 or length > _MAX_BODY_BYTES:
            return self._send(413, {"error": {"code": "PAYLOAD_TOO_LARGE"}})
        try:
            connector_input, echo = build_input(self.rfile.read(length), content_type, self.mailbox)
        except EnvelopeError as error:
            return self._send(400, {"error": {"code": "INVALID_ENVELOPE", "message": str(error)}})
        result = self.connector.process(connector_input)
        response = {
            "schemaVersion": SERVER_SCHEMA_VERSION,
            "status": result.status,
            "failure": asdict(result.failure) if result.failure else None,
            "message": echo or None,
            # Names are restored in everything below; this stays inside RSTN's network.
            "result": result.restored_result,
            "reply": result.restored_reply,
        }
        if self.show_masked:
            response["maskedRequest"] = result.canonical_request  # exactly what left this process
        self._send(200, response)

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="PaCE privacy connector, local HTTP mode")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8788)
    parser.add_argument("--engine-url", default=os.environ.get("PACE_ENGINE_URL", "http://127.0.0.1:8787"))
    parser.add_argument("--engine-timeout", type=float, default=120.0)
    parser.add_argument("--show-masked", action="store_true", help="include the masked request in each response (testing only)")
    parser.add_argument("--mailbox", default=os.environ.get("PACE_MAILBOX_ADDRESSES", ""), help="PaCE's own addresses, comma-separated: thread messages from them are STAFF")
    args = parser.parse_args(argv)
    engine_key = os.environ.get("PACE_ENGINE_API_KEY")
    if not engine_key:
        parser.error("set PACE_ENGINE_API_KEY to the key Synvo issued for the engine")
    if not os.environ.get("PACE_CONNECTOR_NONCE_SECRET"):
        print("warning: PACE_CONNECTOR_NONCE_SECRET is not set; a resend after a restart gets a new masking and the engine rejects it as IDEMPOTENCY_CONFLICT", flush=True)

    ConnectorHandler.connector = MimePrivacyConnector(LocalHttpEngineClient(args.engine_url, engine_key, timeout_seconds=args.engine_timeout))
    ConnectorHandler.api_key = os.environ.get("PACE_CONNECTOR_API_KEY") or None
    ConnectorHandler.show_masked = args.show_masked
    ConnectorHandler.mailbox = frozenset(address.strip().lower() for address in args.mailbox.split(",") if address.strip())
    server = ThreadingHTTPServer((args.host, args.port), ConnectorHandler)
    print(f"connector listening on http://{args.host}:{args.port} -> engine {args.engine_url}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
