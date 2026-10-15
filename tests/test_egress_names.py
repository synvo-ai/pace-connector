"""The egress check must not block ordinary email, and names must still be masked."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

from pace_connector.contracts import ConnectorInput
from pace_connector.masking import LocalPrivacyMasker
from pace_connector.names import known_name_terms, position_spans, shape_spans
from pace_connector.privacy import EgressPrivacySentinel, LocalPrivacyDetector
from pace_connector.server import message_ids
from pace_connector.service import MimePrivacyConnector

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks"))
import egress_rates  # noqa: E402
from egress_corpus import dev_cases, hard_cases, held_out_cases  # noqa: E402


class RecordingClient:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def analyse(self, canonical_request: dict) -> dict:
        self.calls.append(canonical_request)
        return {"schemaVersion": "rstn-headless-http-v0", "result": {"issues": [], "reply": {"status": "NOT_AVAILABLE"}}}


class SentinelTests(unittest.TestCase):
    def test_ordinary_capitalised_phrases_pass(self) -> None:
        sentinel = EgressPrivacySentinel()
        for value in ("Applied Data Analytics", "FlexiMasters in IC Design", "Do I need it?", "If I enrol", "Dear Sir or Madam,", "My NRIC is attached.",
                      "Dear NTU PACE Admissions Team,", "Data Analyst | Brightpath Consulting", "Addressing Issues in AI Ethics and Governance",
                      "Healthcare Management", "General Enquiries", "SkillsFuture Credit", "Tan Tock Seng Hospital", "3 Oct. Reference 88123"):
            with self.subTest(value=value):
                self.assertFalse(sentinel.scan_text(value))

    def test_names_left_in_name_positions_or_with_name_shape_block(self) -> None:
        sentinel = EgressPrivacySentinel()
        for value in ("Thanks,\nSiti", "Dear Jun Hao,", "My name is Nurul Huda and I work here.", "Name: Priscilla Yeo", "Please ask Ms Wong.",
                      "Camellia [[PII_PERSON_abcdefgh_0001]] | Data Analyst", "Mei Xuan Koh", "My friend Grace Ho said", "J. Doe asks", "JANE DOE"):
            with self.subTest(value=value):
                self.assertTrue(sentinel.scan_text(value))
        # A masked sign-off followed by a label line is clean.
        self.assertFalse(sentinel.scan_text("Regards,\n[[PII_PERSON_abcdefgh_0001]]\nMobile: [[PII_PHONE_abcdefgh_0001]]"))

    def test_sender_name_is_checked_even_alone(self) -> None:
        terms = known_name_terms(["Marcus Tan <marcus.tan@example.test>", "PaCE General Enquiries <enquiries@example.test>"])
        self.assertEqual(terms, ("Marcus Tan", "Marcus"))
        self.assertTrue(EgressPrivacySentinel().scan_text("I asked marcus about it.", known_names=terms))
        self.assertFalse(EgressPrivacySentinel().scan_text("I asked about it.", known_names=terms))

    def test_position_and_shape_rules_skip_offices_and_programmes(self) -> None:
        self.assertEqual(position_spans("Dear PaCE team,\n\nThanks,\nThe Admissions Office"), [])
        self.assertEqual(shape_spans("Graduate Certificate in Applied Data Analytics"), [])


class ConnectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.detector = LocalPrivacyDetector()

    def test_signature_sample_is_sent_with_the_full_name_masked(self) -> None:
        client = RecordingClient()
        connector = MimePrivacyConnector(client, LocalPrivacyMasker(self.detector, nonce_secret=b"s" * 32), privacy_detector=self.detector)
        source = next(item for item in dev_cases() if item[0] == "sample-signature")[1]
        result = connector.process(ConnectorInput(source["raw_eml"], **message_ids("test:signature")))
        self.assertEqual(result.status, "COMPLETED", result.failure)
        body = client.calls[0]["enquiry"]["currentMessage"]["body"]
        self.assertIn("Addressing Issues in AI Ethics and Governance", body)
        for word in ("Camellia", "Ong", "Hui", "Shan"):
            self.assertNotIn(word, body)

    def test_rates_on_all_three_sets(self) -> None:
        for label, cases in (("dev", dev_cases()), ("held-out", held_out_cases()), ("hard", hard_cases())):
            result = egress_rates.run(cases, self.detector, verbose=False)
            with self.subTest(set=label):
                self.assertEqual(result["blocked"], [])
                self.assertEqual(result["missed_blocked"] + result["leaked"], [])


if __name__ == "__main__":
    unittest.main()
