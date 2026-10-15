from __future__ import annotations

import json
from pathlib import Path
import unittest

from pace_connector.contracts import ConnectorInput, PriorIssue, ThreadMessage
from pace_connector.errors import PrivacyDetectorFailureError, PrivacyScopeUnsupportedError
from pace_connector.masking import LocalPrivacyMasker, MaskingResult
from pace_connector.privacy import EgressPrivacyGate, EgressPrivacySentinel, LocalPrivacyDetector, public_institutional_entity_registry_provenance
from pace_connector.service import MimePrivacyConnector


class RecordingClient:
    def __init__(self): self.calls: list[dict] = []
    def analyse(self, payload):
        self.calls.append(payload)
        message = payload["enquiry"]["currentMessage"]
        return {"result": {"reply": {"status": "AVAILABLE", "subject": message["subject"], "body": message["body"]}}}


class LeakySession:
    def mask(self, text): return MaskingResult(text, ())
    def restore(self, text): return text


class LeakyMasker:
    def new_session(self): return LeakySession()


class BrokenDetector:
    def find(self, _text): raise PrivacyDetectorFailureError()


def connector_input(**values) -> ConnectorInput:
    default = {
        "raw_eml": b"From: Dr Jane Doe <jane.doe@example.test>\nSubject: Programme enquiry\n\nDr Jane Doe asks about the Advanced Professional Certificate in Data Science and AI. Call +65 8123 4567. Reference SYN-CASE-001.",
        "request_id": "rstn_req_00000000000000000000000000000001", "correlation_id": "rstn_cor_00000000000000000000000000000001", "idempotency_key": "rstn_idem_00000000000000000000000000000001",
    }
    default.update(values)
    return ConnectorInput(**default)


class LocalPrivacyDetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.detector = LocalPrivacyDetector()

    def test_layered_detector_finds_structural_and_person_categories_without_masking_business_terms(self) -> None:
        text = "Dr Jane Doe jane.doe@example.test +65 8123-4567 S1234567A Reference REF-CASE-001"
        categories = {finding.category for finding in self.detector.find(text)}
        self.assertTrue({"PERSON", "EMAIL", "PHONE", "NRIC_FIN", "REFERENCE"}.issubset(categories))
        public = "NTU PaCE Advanced Professional Certificate in Data Science and AI starts on 1 May 2026 and costs $1200."
        self.assertEqual(self.detector.find(public), ())

    def test_request_session_is_stable_across_message_thread_and_prior_issue(self) -> None:
        session = LocalPrivacyMasker(self.detector).new_session()
        first = session.mask("Jane Doe").masked_text
        second = session.mask("Please reply to Jane Doe").masked_text
        self.assertIn(first, second)
        self.assertEqual(session.restore(second), "Please reply to Jane Doe")

    def test_unsupported_script_is_not_silently_privacy_clean(self) -> None:
        with self.assertRaises(PrivacyScopeUnsupportedError):
            self.detector.find("姓名 Jane Doe")

    def test_connector_owned_public_entity_registry_is_versioned_and_bound_to_the_frozen_world(self) -> None:
        self.assertEqual(public_institutional_entity_registry_provenance(), {
            "schemaVersion": "rstn-public-entity-registry-v1",
            "registryId": "rstn-poc-synthetic-public-institutional-entities",
            "registryVersion": "1.1.0",
            "sourceWorldDigest": "f9a84c3e1e65e3736ec0ac65da9971d840c0eb889ae4722ff07c50221c06ec4f",
        })


class EgressPrivacyGateTests(unittest.TestCase):
    def test_every_packaged_public_entity_passes_natural_capitalisation_but_held_out_people_do_not(self) -> None:
        sentinel = EgressPrivacySentinel()
        detector = LocalPrivacyDetector()
        snapshot_path = Path(__file__).resolve().parents[1] / "pace_connector" / "public_institutional_entities.v1.json"
        snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
        # The full packaged registry is exercised here.
        entities = [name for record in snapshot["entities"] for name in (record["displayName"], *record["aliases"])]
        self.assertIn("Cloud Operations", entities)
        self.assertTrue({"Finance Support", "Credit Review", "Academic Records"}.issubset(entities))
        for value in entities:
            with self.subTest(public_entity=value):
                self.assertEqual(detector.find(value), ())
                self.assertFalse(sentinel.scan_text(value))
                client = RecordingClient()
                result = MimePrivacyConnector(client).process(connector_input(
                    raw_eml=(f"From: synthetic.sender@example.test\nSubject: {value}\n\n{value}").encode(),
                ))
                self.assertEqual(result.status, "COMPLETED")
                self.assertEqual(result.canonical_request["enquiry"]["currentMessage"]["body"], value)
                self.assertEqual(len(client.calls), 1)
        for value in ("Alice Example", "Li Kai", "José García", "Mira Sample"):
            with self.subTest(held_out_person=value):
                self.assertTrue(sentinel.scan_text(value))

    def test_mixed_person_and_controlled_public_entity_masks_only_the_person(self) -> None:
        person, programme = "Alice Example", "Applied AI Certificate"
        source = f"{person} is asking about {programme}"
        session = LocalPrivacyMasker(LocalPrivacyDetector()).new_session()
        masked = session.mask(source).masked_text
        self.assertNotIn(person, masked)
        self.assertIn(programme, masked)
        self.assertFalse(EgressPrivacySentinel().scan_text(masked))

    def test_mixed_person_and_controlled_service_team_masks_only_the_person(self) -> None:
        person, service_team = "Alice Example", "Finance Support"
        source = f"{person} needs {service_team}"
        session = LocalPrivacyMasker(LocalPrivacyDetector()).new_session()
        masked = session.mask(source).masked_text
        self.assertNotIn(person, masked)
        self.assertIn(service_team, masked)
        self.assertFalse(EgressPrivacySentinel().scan_text(masked))

    def test_leaked_outbound_pii_is_blocked_before_any_engine_call(self) -> None:
        client = RecordingClient()
        result = MimePrivacyConnector(client, masking_engine=LeakyMasker()).process(connector_input())
        self.assertEqual(result.status, "REQUIRES_MANUAL_HANDLING")
        self.assertEqual(result.failure.code, "EGRESS_PRIVACY_CHECK_FAILED")
        self.assertEqual(client.calls, [])

    def test_detector_failure_is_fail_closed_before_http(self) -> None:
        client = RecordingClient()
        result = MimePrivacyConnector(client, privacy_detector=BrokenDetector()).process(connector_input())
        self.assertEqual(result.status, "REQUIRES_MANUAL_HANDLING")
        self.assertEqual(result.failure.code, "PRIVACY_DETECTOR_FAILURE")
        self.assertEqual(client.calls, [])

    def test_all_outbound_free_text_is_masked_and_business_context_survives(self) -> None:
        client = RecordingClient()
        result = MimePrivacyConnector(client).process(connector_input(
            permitted_thread=(ThreadMessage("thread", "STAFF", "Dr Jane Doe should provide a programme code."),),
            prior_issues=(PriorIssue("prior", "Jane Doe requested intake details", ("Contact jane.doe@example.test",)),),
        ))
        self.assertEqual(result.status, "COMPLETED")
        outbound = str(result.canonical_request)
        for raw in ("Jane Doe", "jane.doe@example.test", "+65 8123 4567", "SYN-CASE-001"):
            self.assertNotIn(raw, outbound)
        self.assertIn("Advanced Professional Certificate in Data Science and AI", outbound)
        self.assertEqual(len(client.calls), 1)


if __name__ == "__main__": unittest.main()
