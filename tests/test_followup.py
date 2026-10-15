"""Follow-ups in HTTP mode: earlier messages and issues sent in an envelope."""

from __future__ import annotations

import base64
import copy
import json
import unittest
from pathlib import Path

from pace_connector.masking import LocalPrivacyMasker
from pace_connector.privacy import LocalPrivacyDetector
from pace_connector.server import EnvelopeError, build_input
from pace_connector.service import MimePrivacyConnector

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
ENVELOPE = json.loads((EXAMPLES / "graph_followup.json").read_text())
MAILBOX = frozenset({"enquiries@pace-mock.example"})


class RecordingClient:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def analyse(self, canonical_request: dict) -> dict:
        self.calls.append(canonical_request)
        return {"schemaVersion": "rstn-headless-http-v0", "result": {"issues": [], "reply": {"status": "NOT_PRODUCED"}}}


def post(envelope: dict, mailbox: frozenset[str] = MAILBOX):
    return build_input(json.dumps(envelope).encode(), "application/json", mailbox)


class EnvelopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.detector = LocalPrivacyDetector()

    def process(self, envelope: dict) -> tuple[dict, object]:
        client = RecordingClient()
        connector = MimePrivacyConnector(client, LocalPrivacyMasker(self.detector, nonce_secret=b"s" * 32), privacy_detector=self.detector)
        connector_input, echo = post(envelope)
        result = connector.process(connector_input)
        self.assertEqual(result.status, "COMPLETED", result.failure)
        return client.calls[0], echo

    def test_thread_and_prior_issues_reach_the_engine_masked(self) -> None:
        request, echo = self.process(ENVELOPE)
        enquiry = request["enquiry"]
        self.assertEqual([item["direction"] for item in enquiry["permittedThread"]], ["USER", "STAFF"])
        self.assertIn("Biomaterials (Asynchronous e-learning)", enquiry["permittedThread"][0]["body"])
        self.assertIn("9 August 2026", enquiry["permittedThread"][1]["body"])
        self.assertEqual(enquiry["priorIssues"][0]["issueId"], "prior-001")
        self.assertIn("Biomaterials", enquiry["priorIssues"][0]["summary"])
        outbound = json.dumps(request)
        for raw in ("Mei Xuan", "Koh", "Jun Hao", "9234 5678", "meixuan"):
            self.assertNotIn(raw, outbound)
        # One placeholder per person across the current message, the thread and prior issues.
        sign_off = enquiry["currentMessage"]["body"].rsplit("\n", 1)[-1]
        self.assertIn(sign_off, enquiry["permittedThread"][0]["body"])
        self.assertIn(sign_off, enquiry["priorIssues"][0]["summary"])
        self.assertEqual(echo["conversationId"], ENVELOPE["message"]["conversationId"])

    def test_text_items_and_eml_are_accepted(self) -> None:
        eml = (EXAMPLES / "scholarship.eml").read_bytes()
        envelope = {"eml": base64.b64encode(eml).decode(), "thread": [{"direction": "STAFF", "body": "The next intake is in January."}]}
        request, _echo = self.process(envelope)
        self.assertEqual(request["enquiry"]["permittedThread"], [{"messageId": "thread-001", "direction": "STAFF", "body": "The next intake is in January."}])

    def test_same_envelope_same_ids_different_context_new_ids(self) -> None:
        first, again = post(ENVELOPE)[0], post(copy.deepcopy(ENVELOPE))[0]
        self.assertEqual(first.idempotency_key, again.idempotency_key)
        shorter = dict(ENVELOPE, thread=ENVELOPE["thread"][:1])
        self.assertNotEqual(first.idempotency_key, post(shorter)[0].idempotency_key)
        bare = post(ENVELOPE["message"])[0]
        self.assertEqual(bare.permitted_thread, ())
        self.assertNotEqual(bare.idempotency_key, first.idempotency_key)

    def test_invalid_envelopes_are_rejected(self) -> None:
        for bad in ({"message": ENVELOPE["message"], "eml": "eA=="}, {"message": ENVELOPE["message"], "extra": 1},
                    {"message": ENVELOPE["message"], "thread": [{"body": "no direction"}]},
                    {"message": ENVELOPE["message"], "thread": [{"direction": "ADMIN", "body": "x"}]},
                    {"message": ENVELOPE["message"], "priorIssues": [{"summary": " "}]}, {"eml": "not base64!"}):
            with self.subTest(bad=list(bad)), self.assertRaises(EnvelopeError):
                post(bad)
        with self.assertRaisesRegex(EnvelopeError, "--mailbox"):
            post(ENVELOPE, mailbox=frozenset())

    def test_long_threads_keep_the_newest_messages(self) -> None:
        items = [{"direction": "USER", "body": f"message {index}"} for index in range(40)]
        connector_input, _echo = post({"message": ENVELOPE["message"], "thread": items})
        self.assertEqual(len(connector_input.permitted_thread), 30)
        self.assertEqual(connector_input.permitted_thread[-1].body, "message 39")


if __name__ == "__main__":
    unittest.main()
