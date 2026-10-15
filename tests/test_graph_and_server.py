from __future__ import annotations

import base64
import copy
import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from pace_connector.contracts import ConnectorInput, ConnectorLimits
from pace_connector.graph import parse_graph_message
from pace_connector.masking import LocalPrivacyMasker
from pace_connector.mime import parse_rfc5322
from pace_connector.privacy import LocalPrivacyDetector
from pace_connector.server import ConnectorHandler, build_input, message_ids
from pace_connector.service import MimePrivacyConnector

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
GRAPH = json.loads((EXAMPLES / "graph_message.json").read_text())


class EchoClient:
    """Returns the masked body as the issue summary and reply, like an engine quoting the sender."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def analyse(self, canonical_request: dict) -> dict:
        self.calls.append(canonical_request)
        message = canonical_request["enquiry"]["currentMessage"]
        return {"schemaVersion": "rstn-headless-http-v0", "result": {
            "issues": [{"issueId": "ISSUE-001", "summary": message["body"], "handoff": {"note": "Call " + message["body"][-60:]}}],
            "reply": {"status": "AVAILABLE", "subject": message["subject"], "body": message["body"]},
        }}


def graph_input(message: dict, key_suffix: str = "1") -> ConnectorInput:
    ids = message_ids("graph:test-" + key_suffix)
    return ConnectorInput(b"", **ids, graph_message=message)


class GraphParserTests(unittest.TestCase):
    def test_html_body_quote_block_is_separated(self) -> None:
        parsed = parse_graph_message(GRAPH, ConnectorLimits())
        self.assertIn("funding options", parsed.current_body)
        self.assertNotIn("next intake starts", parsed.current_body)
        self.assertIn("next intake starts", parsed.quoted_history)
        self.assertEqual(parsed.local_sender, "Tan Mei Ling <meiling.tan@example.test>")
        self.assertEqual(parsed.attachments, ())

    def test_graph_bytes_and_eml_give_the_same_current_body(self) -> None:
        from_graph = parse_graph_message(json.dumps(GRAPH).encode(), ConnectorLimits())
        from_eml = parse_rfc5322((EXAMPLES / "scholarship.eml").read_bytes(), ConnectorLimits())
        self.assertEqual(from_graph.current_body, from_eml.current_body)

    def test_outlook_reply_block_is_separated(self) -> None:
        message = copy.deepcopy(GRAPH)
        message["body"]["content"] = '<div>Can I defer to the next intake?</div><hr id="stopSpelling"><div id="divRplyFwdMsg"><b>From:</b> PaCE</div><div>Old text</div>'
        parsed = parse_graph_message(message, ConnectorLimits())
        self.assertEqual(parsed.current_body, "Can I defer to the next intake?")
        self.assertIn("Old text", parsed.quoted_history)

    def test_plain_text_outlook_original_message(self) -> None:
        message = copy.deepcopy(GRAPH)
        message["body"] = {"contentType": "text", "content": "New question here.\r\n\r\n-----Original Message-----\r\nFrom: PaCE\r\nOld text"}
        parsed = parse_graph_message(message, ConnectorLimits())
        self.assertEqual(parsed.current_body, "New question here.")

    def test_expanded_file_attachment_is_read_locally_and_unexpanded_is_recorded(self) -> None:
        message = copy.deepcopy(GRAPH)
        message["attachments"] = [
            {"@odata.type": "#microsoft.graph.fileAttachment", "name": "a.png", "contentType": "image/png", "isInline": False, "contentBytes": base64.b64encode(b"png-bytes").decode()},
            {"@odata.type": "#microsoft.graph.itemAttachment", "name": "fwd", "contentType": "message/rfc822"},
        ]
        parsed = parse_graph_message(message, ConnectorLimits())
        self.assertEqual([a.content_state for a in parsed.attachments], ["NOT_READ", "UNSUPPORTED"])
        self.assertEqual(parsed.local_attachments[0].content, b"png-bytes")
        unexpanded = dict(GRAPH, hasAttachments=True)
        self.assertEqual(len(parse_graph_message(unexpanded, ConnectorLimits()).attachments), 1)

    def test_malformed_graph_input_requires_manual_handling(self) -> None:
        for bad in (b"not json", b"[]", json.dumps({"subject": "x"}).encode(), json.dumps(dict(GRAPH, body={"contentType": "html", "content": "   "})).encode()):
            result = MimePrivacyConnector(EchoClient()).process(ConnectorInput(b"", **message_ids("graph:bad"), graph_message=bad))
            self.assertEqual(result.status, "REQUIRES_MANUAL_HANDLING")
            self.assertIn(result.failure.code, {"MALFORMED_EMAIL", "BODY_UNAVAILABLE"})


class GraphConnectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.detector = LocalPrivacyDetector()

    def connector(self, client: EchoClient, secret: bytes = b"s" * 32) -> MimePrivacyConnector:
        return MimePrivacyConnector(client, LocalPrivacyMasker(self.detector, nonce_secret=secret), privacy_detector=self.detector)

    def test_graph_message_is_masked_and_every_result_field_restored(self) -> None:
        client = EchoClient()
        result = self.connector(client).process(graph_input(GRAPH))
        self.assertEqual(result.status, "COMPLETED", result.failure)
        outbound = json.dumps(client.calls[0])
        for raw in ("Tan Mei Ling", "9123 4567", "meiling.tan", "next intake starts"):
            self.assertNotIn(raw, outbound)
        issue = result.restored_result["issues"][0]
        self.assertIn("+65 9123 4567", issue["summary"])
        self.assertIn("Tan Mei Ling", issue["handoff"]["note"])
        self.assertIn("Tan Mei Ling", result.restored_reply["body"])

    def test_same_idempotency_key_gives_identical_request(self) -> None:
        client = EchoClient()
        self.connector(client).process(graph_input(GRAPH))
        self.connector(client).process(graph_input(GRAPH))  # a restarted connector with the same secret
        self.assertEqual(client.calls[0], client.calls[1])
        self.connector(client, secret=b"t" * 32).process(graph_input(GRAPH))
        self.assertNotEqual(client.calls[0]["enquiry"]["currentMessage"]["body"], client.calls[2]["enquiry"]["currentMessage"]["body"])

    def test_truncated_placeholder_is_dropped_on_restore(self) -> None:
        class Truncating(EchoClient):
            def analyse(self, canonical_request: dict) -> dict:
                response = super().analyse(canonical_request)
                body = response["result"]["issues"][0]["summary"]
                response["result"]["issues"][0]["summary"] = body[: body.rindex("[[PII_") + 12]
                return response
        result = self.connector(Truncating()).process(graph_input(GRAPH))
        self.assertNotIn("[[PII_", result.restored_result["issues"][0]["summary"])
        for cut in (1, 2, 5):
            class Short(EchoClient):
                def analyse(self, canonical_request: dict, cut=cut) -> dict:
                    response = super().analyse(canonical_request)
                    body = response["result"]["issues"][0]["summary"]
                    response["result"]["issues"][0]["summary"] = body[: body.rindex("[[PII_") + cut]
                    return response
            summary = self.connector(Short()).process(graph_input(GRAPH)).restored_result["issues"][0]["summary"]
            self.assertTrue(summary.endswith("…"), summary[-20:])


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        detector = LocalPrivacyDetector()
        cls.client = EchoClient()
        ConnectorHandler.connector = MimePrivacyConnector(cls.client, LocalPrivacyMasker(detector, nonce_secret=b"s" * 32), privacy_detector=detector)
        ConnectorHandler.api_key = "local-key"
        ConnectorHandler.show_masked = False
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), ConnectorHandler)
        cls.url = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def post(self, body: bytes, content_type: str = "application/json", key: str = "local-key") -> tuple[int, dict]:
        request = Request(self.url + "/v0/messages", data=body, method="POST", headers={"content-type": content_type, "x-api-key": key})
        try:
            with urlopen(request, timeout=30) as response:
                return response.status, json.loads(response.read())
        except HTTPError as error:
            return error.code, json.loads(error.read())

    def test_graph_post_returns_restored_result_and_graph_refs(self) -> None:
        status, body = self.post(json.dumps(GRAPH).encode())
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "COMPLETED")
        self.assertEqual(body["message"]["conversationId"], GRAPH["conversationId"])
        self.assertIn("Tan Mei Ling", body["reply"]["body"])
        self.assertNotIn("maskedRequest", body)

    def test_eml_post_and_resend_send_the_same_request(self) -> None:
        eml = (EXAMPLES / "scholarship.eml").read_bytes()
        before = len(self.client.calls)
        self.assertEqual(self.post(eml, "message/rfc822")[1]["status"], "COMPLETED")
        self.assertEqual(self.post(eml, "message/rfc822")[1]["status"], "COMPLETED")
        self.assertEqual(self.client.calls[before], self.client.calls[before + 1])

    def test_auth_and_media_type_are_enforced(self) -> None:
        self.assertEqual(self.post(b"{}", key="wrong")[0], 401)
        self.assertEqual(self.post(b"{}", content_type="text/plain")[0], 415)

    def test_ids_follow_the_connector_contract(self) -> None:
        connector_input, _ = build_input(json.dumps(GRAPH).encode(), "application/json")
        self.assertRegex(connector_input.request_id, r"^rstn_req_[0-9a-f]{32}$")
        self.assertRegex(connector_input.correlation_id, r"^rstn_cor_[0-9a-f]{32}$")
        self.assertRegex(connector_input.idempotency_key, r"^rstn_idem_[0-9a-f]{32}$")


if __name__ == "__main__":
    unittest.main()
