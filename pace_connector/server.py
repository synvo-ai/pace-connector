"""Local HTTP mode: RSTN's system posts each email here; the connector masks it, calls the
engine and answers with the result, names restored. Runs inside RSTN's network.

    PACE_ENGINE_API_KEY=... python -m pace_connector.server --engine-url https://<engine> --port 8788

POST /v0/messages
    Content-Type: application/json     one Microsoft Graph message (as returned by
                                       GET /users/{id}/messages/{id}, optionally ?$expand=attachments)
    Content-Type: message/rfc822       one raw .eml
GET  /v0/health

Every outcome of processing an email is HTTP 200 with `status` COMPLETED or
REQUIRES_MANUAL_HANDLING. Non-200 is only for the HTTP call itself (401, 404, 413, 415).
"""

from __future__ import annotations

import argparse
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
from .contracts import CONNECTOR_CONTRACT_VERSION, ConnectorInput, ConnectorLimits
from .errors import ConnectorError
from .graph import graph_refs, load_graph_message
from .service import MimePrivacyConnector

SERVER_SCHEMA_VERSION = "pace-connector-http-v0"
_MAX_BODY_BYTES = ConnectorLimits().max_raw_bytes * 2


def message_ids(identity: str) -> dict[str, str]:
    """The three engine IDs, derived from the message so a resend of the same email is
    byte-identical and the engine replays its first answer instead of running again."""
    digest = lambda kind: hashlib.sha256(f"{kind}:{identity}".encode("utf-8")).hexdigest()[:32]
    return {"request_id": "rstn_req_" + digest("req"), "correlation_id": "rstn_cor_" + digest("cor"), "idempotency_key": "rstn_idem_" + digest("idem")}


def build_input(body: bytes, content_type: str) -> tuple[ConnectorInput, dict[str, str | None]]:
    limits = ConnectorLimits()
    if content_type == "message/rfc822":
        try:
            message_id = str(BytesParser(policy=policy.default).parsebytes(body, headersonly=True).get("message-id", "")).strip()
        except Exception:
            message_id = ""
        identity = "eml:" + (message_id or hashlib.sha256(body).hexdigest())
        return ConnectorInput(body, **message_ids(identity), limits=limits), {}
    try:
        message: Any = load_graph_message(body, limits)
        refs = graph_refs(message)
    except ConnectorError:
        message, refs = body, None  # the connector reports it as malformed
    identity = "graph:" + ((refs and (refs.message_id or refs.internet_message_id)) or hashlib.sha256(body).hexdigest())
    echo = {"id": refs.message_id, "internetMessageId": refs.internet_message_id, "conversationId": refs.conversation_id} if refs else {}
    return ConnectorInput(b"", **message_ids(identity), limits=limits, graph_message=message), echo


class ConnectorHandler(BaseHTTPRequestHandler):
    connector: MimePrivacyConnector
    api_key: str | None = None
    show_masked = False
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
        connector_input, echo = build_input(self.rfile.read(length), content_type)
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
    args = parser.parse_args(argv)
    engine_key = os.environ.get("PACE_ENGINE_API_KEY")
    if not engine_key:
        parser.error("set PACE_ENGINE_API_KEY to the key Synvo issued for the engine")
    if not os.environ.get("PACE_CONNECTOR_NONCE_SECRET"):
        print("warning: PACE_CONNECTOR_NONCE_SECRET is not set; a resend after a restart gets a new masking and the engine rejects it as IDEMPOTENCY_CONFLICT", flush=True)

    ConnectorHandler.connector = MimePrivacyConnector(LocalHttpEngineClient(args.engine_url, engine_key, timeout_seconds=args.engine_timeout))
    ConnectorHandler.api_key = os.environ.get("PACE_CONNECTOR_API_KEY") or None
    ConnectorHandler.show_masked = args.show_masked
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
