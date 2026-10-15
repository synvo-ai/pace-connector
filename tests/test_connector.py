from __future__ import annotations

import json
import logging
import unittest
from io import BytesIO

from PIL import Image
from pace_connector.attachments import LocalAttachmentProcessor, OcrToken, SyntheticFixtureDetector
from pace_connector.contracts import AttachmentMetadata, ConnectorInput, ConnectorLimits, LocalAttachment, PriorIssue, ThreadMessage
from pace_connector.errors import EngineContractRejectedError, EngineUnavailableError, MaskingFailureError
from pace_connector.masking import SyntheticFixtureMasker
from pace_connector.mime import parse_rfc5322
from pace_connector.service import MimePrivacyConnector


SYNTHETIC_EML = b"From: Alice Example <alice.synthetic@example.test>\nTo: pace@example.test\nSubject: Intake and payment\nMessage-ID: <synthetic-001@example.test>\n\nHello, my name is Alice Example.\nMy synthetic phone number is +65 8123 4567.\n\nWhat is the intake status for the Advanced Professional Certificate in Data Science and AI?\n\nI have also attached my payment receipt. Can you confirm that payment has been received?\n"


class RecordingClient:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def analyse(self, canonical_request: dict) -> dict:
        self.calls.append(canonical_request)
        message = canonical_request["enquiry"]["currentMessage"]
        return {"schemaVersion": "rstn-headless-http-v0", "internalContractVersion": "headless-correspondence-v1", "result": {"reply": {"status": "AVAILABLE", "subject": message["subject"], "body": message["body"]}}}


class RaisingClient:
    def __init__(self, error: Exception) -> None:
        self.error = error
        self.called = False

    def analyse(self, canonical_request: dict) -> dict:
        self.called = True
        raise self.error


class FailingMasker:
    def new_session(self):
        raise MaskingFailureError()


class TwoPassAttachmentOcr:
    """Deterministic local OCR fixture: source PII then safe verification text."""

    def __init__(self) -> None:
        self.calls = 0

    def read(self, _image):
        self.calls += 1
        if self.calls == 1:
            return [
                OcrToken("Alice", 0, ((.1, .1), (.3, .1), (.3, .2), (.1, .2)), 1.0),
                OcrToken("Example", 0, ((.31, .1), (.6, .1), (.6, .2), (.31, .2)), 1.0),
                OcrToken("Receipt", 0, ((.1, .3), (.4, .3), (.4, .4), (.1, .4)), 1.0),
            ]
        return [
            OcrToken("redacted", 0, ((.1, .1), (.4, .1), (.4, .2), (.1, .2)), 1.0),
            OcrToken("receipt", 0, ((.1, .3), (.4, .3), (.4, .4), (.1, .4)), 1.0),
        ]


def connector_input(raw: bytes = SYNTHETIC_EML, **kwargs) -> ConnectorInput:
    values = {"raw_eml": raw, "request_id": "rstn_req_00000000000000000000000000000002", "correlation_id": "rstn_cor_00000000000000000000000000000002", "idempotency_key": "rstn_idem_00000000000000000000000000000002"}
    values.update(kwargs)
    return ConnectorInput(**values)


class MimeParserTests(unittest.TestCase):
    def test_plain_text_and_encoded_headers_are_decoded(self) -> None:
        raw = b"From: =?utf-8?b?QWxpY2UgRXhhbXBsZQ==?= <alice.synthetic@example.test>\nSubject: =?utf-8?b?SW50YWtlIOKAnCBwYXltZW50?=\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: quoted-printable\n\nAlice=20Example=20asks=20about=20intake.\n"
        parsed = parse_rfc5322(raw, ConnectorLimits())
        self.assertIn("Intake", parsed.subject)
        self.assertIn("Alice Example", parsed.current_body)

    def test_html_and_alternative_prefer_plain_text(self) -> None:
        alternative = b"From: Alice Example <alice.synthetic@example.test>\nSubject: HTML\nMIME-Version: 1.0\nContent-Type: multipart/alternative; boundary=alt\n\n--alt\nContent-Type: text/plain; charset=utf-8\n\nPlain current message\n--alt\nContent-Type: text/html; charset=utf-8\n\n<p>HTML current message</p><script>never_include()</script>\n--alt--\n"
        self.assertEqual(parse_rfc5322(alternative, ConnectorLimits()).current_body, "Plain current message")
        html = b"From: Alice Example <alice.synthetic@example.test>\nSubject: HTML\nContent-Type: text/html; charset=utf-8\n\n<p>Hello <b>Alice Example</b></p><script>ignored()</script>"
        parsed_html = parse_rfc5322(html, ConnectorLimits())
        self.assertIn("Hello Alice Example", parsed_html.current_body)
        self.assertNotIn("ignored", parsed_html.current_body)

    def test_mixed_inline_image_and_attachment_are_metadata_only(self) -> None:
        mixed = b"From: Alice Example <alice.synthetic@example.test>\nSubject: Receipt\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=mix\n\n--mix\nContent-Type: text/plain; charset=utf-8\n\nPlease see attached receipt.\n--mix\nContent-Type: image/png\nContent-Disposition: inline; filename=receipt.png\nContent-Transfer-Encoding: base64\n\naGVsbG8=\n--mix\nContent-Type: application/pdf\nContent-Disposition: attachment; filename=payment.pdf\nContent-Transfer-Encoding: base64\n\naGVsbG8=\n--mix--\n"
        parsed = parse_rfc5322(mixed, ConnectorLimits())
        self.assertEqual(len(parsed.attachments), 2)
        self.assertEqual([item.content_state for item in parsed.attachments], ["NOT_READ", "NOT_READ"])
        self.assertIn("Please see attached receipt", parsed.current_body)

    def test_attachment_containers_never_contribute_body_or_canonical_content(self) -> None:
        raw = b"From: Alice Example <alice.synthetic@example.test>\nSubject: Outer body\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=outer\n\n--outer\nContent-Type: text/plain; charset=utf-8\n\nOuter message only.\n--outer\nContent-Type: message/rfc822\nContent-Disposition: attachment; filename=forwarded.eml\n\nFrom: Alice Example <alice.synthetic@example.test>\nSubject: Attached\nContent-Type: text/plain; charset=utf-8\n\nATTACHED_INTERNAL_DO_NOT_FORWARD Alice Example +65 8123 4567\n--outer\nContent-Type: multipart/mixed; boundary=nested\nContent-Disposition: attachment; filename=bundle.mime\n\n--nested\nContent-Type: text/plain; charset=utf-8\n\nNESTED_INTERNAL_DO_NOT_FORWARD Alice Example\n--nested--\n--outer--\n"
        parsed = parse_rfc5322(raw, ConnectorLimits())
        self.assertEqual(parsed.current_body, "Outer message only.")
        self.assertNotIn("ATTACHED_INTERNAL_DO_NOT_FORWARD", parsed.current_body)
        self.assertNotIn("NESTED_INTERNAL_DO_NOT_FORWARD", parsed.current_body)
        self.assertEqual(len(parsed.attachments), 2)
        result = MimePrivacyConnector(RecordingClient()).process(connector_input(raw))
        self.assertEqual(result.status, "COMPLETED")
        outbound = json.dumps(result.canonical_request)
        for value in ("ATTACHED_INTERNAL_DO_NOT_FORWARD", "NESTED_INTERNAL_DO_NOT_FORWARD", "Alice Example", "+65 8123 4567"):
            self.assertNotIn(value, outbound)
        self.assertEqual(result.canonical_request["enquiry"]["permittedThread"], [])

    def test_application_leaf_without_filename_is_unread_unsupported_attachment(self) -> None:
        raw = b"From: Alice Example <alice.synthetic@example.test>\nSubject: PDF\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=x\n\n--x\nContent-Type: text/plain\n\nOuter body.\n--x\nContent-Type: application/pdf\n\nPDF_INTERNAL_DO_NOT_READ\n--x--\n"
        parsed = parse_rfc5322(raw, ConnectorLimits())
        self.assertEqual(parsed.current_body, "Outer body.")
        self.assertEqual(len(parsed.attachments), 1)
        self.assertEqual(parsed.attachments[0].content_state, "UNSUPPORTED")
        self.assertNotIn("PDF_INTERNAL_DO_NOT_READ", parsed.current_body)

    def test_quoted_history_is_separated_not_forwarded_as_permitted_thread(self) -> None:
        raw = b"From: Alice Example <alice.synthetic@example.test>\nSubject: Follow up\n\nCurrent question\n\nOn Mon, Jan 1, 2026 at 9:00 AM PaCE wrote:\n> Earlier content\n"
        parsed = parse_rfc5322(raw, ConnectorLimits())
        self.assertEqual(parsed.current_body, "Current question")
        self.assertIn("Earlier content", parsed.quoted_history)

    def test_malformed_unavailable_and_limits_fail_closed(self) -> None:
        with self.assertRaises(Exception):
            parse_rfc5322(b"not an RFC 5322 message", ConnectorLimits())
        with self.assertRaises(Exception):
            parse_rfc5322(SYNTHETIC_EML, ConnectorLimits(max_raw_bytes=10))
        mixed = b"From: Alice Example <alice.synthetic@example.test>\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=x\n\n--x\nContent-Type: text/plain\n\nbody\n--x\nContent-Type: application/pdf\nContent-Disposition: attachment; filename=a.pdf\n\na\n--x--\n"
        with self.assertRaises(Exception):
            parse_rfc5322(mixed, ConnectorLimits(max_attachments=0))


class ConnectorServiceTests(unittest.TestCase):
    def test_synthetic_pii_is_masked_before_http_and_only_reply_is_restored(self) -> None:
        client = RecordingClient()
        result = MimePrivacyConnector(client).process(connector_input())
        self.assertEqual(result.status, "COMPLETED")
        outbound = json.dumps(result.canonical_request)
        for raw in ("Alice Example", "alice.synthetic@example.test", "+65 8123 4567", "pace@example.test"):
            self.assertNotIn(raw, outbound)
        self.assertIn("[[PII_PERSON_", outbound)
        self.assertEqual(result.canonical_request["enquiry"]["attachmentEvidence"], [])
        self.assertIn("Alice Example", result.restored_reply["body"])
        self.assertNotIn("Alice Example", json.dumps(result.engine_result))

    def test_attachment_metadata_never_claims_contents(self) -> None:
        raw = b"From: Alice Example <alice.synthetic@example.test>\nSubject: Receipt\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=x\n\n--x\nContent-Type: text/plain\n\nPlease see the attached receipt. Payment is received.\n--x\nContent-Type: application/pdf\nContent-Disposition: attachment; filename=alice-receipt.pdf\n\nunread bytes\n--x--\n"
        result = MimePrivacyConnector(RecordingClient()).process(connector_input(raw))
        evidence = result.canonical_request["enquiry"]["attachmentEvidence"][0]
        self.assertEqual(evidence["contentState"], "NOT_READ")
        self.assertEqual(evidence["extractionMethod"], "NONE")
        self.assertEqual(evidence["provenance"], "SENDER_PROVIDED")
        self.assertEqual(evidence["privacyTransformation"], "CONNECTOR_MASKED")
        self.assertNotIn("alice-receipt.pdf", json.dumps(evidence))
        self.assertNotIn("received", evidence["excerpt"].lower())

    def test_sender_attachment_authority_stays_non_institutional_for_future_ocr_work(self) -> None:
        result = MimePrivacyConnector(RecordingClient()).process(connector_input(
            externally_observed_attachments=(AttachmentMetadata("receipt.pdf", "application/pdf", None, "attachment", "METADATA_ONLY"),),
        ))
        evidence = result.canonical_request["enquiry"]["attachmentEvidence"][0]
        self.assertEqual(evidence["provenance"], "SENDER_PROVIDED")
        self.assertEqual(evidence["privacyTransformation"], "CONNECTOR_MASKED")
        self.assertEqual(evidence["extractionMethod"], "NONE")
        self.assertNotIn("institutional", evidence["excerpt"].lower())
        self.assertNotIn("payment has been received", json.dumps(evidence).lower())

    def test_attachment_failure_is_metadata_only_and_does_not_block_body_analysis(self) -> None:
        client = RecordingClient()
        result = MimePrivacyConnector(client).process(connector_input(
            local_attachments=(LocalAttachment(
                AttachmentMetadata("unreadable.bin", "application/octet-stream", 4, "attachment"),
                b"not an image or PDF",
            ),),
        ))
        self.assertEqual(result.status, "COMPLETED")
        self.assertEqual(len(client.calls), 1)
        evidence = result.canonical_request["enquiry"]["attachmentEvidence"][0]
        self.assertEqual(evidence["processingStatus"], "UNSUPPORTED")
        self.assertEqual(evidence["contentState"], "NOT_READ")
        self.assertEqual(evidence["provenance"], "SENDER_PROVIDED")
        self.assertEqual(evidence["extractionMethod"], "NONE")

    def test_pixel_redacted_attachment_egress_contract_completes_once(self) -> None:
        image = Image.new("RGB", (600, 240), "white")
        stream = BytesIO(); image.save(stream, format="PNG")
        local = LocalAttachment(AttachmentMetadata("receipt.png", "image/png", len(stream.getvalue()), "attachment"), stream.getvalue())
        processor = LocalAttachmentProcessor(ocr_engine=TwoPassAttachmentOcr(), detector=SyntheticFixtureDetector())
        client = RecordingClient()
        result = MimePrivacyConnector(client, attachment_processor=processor).process(connector_input(local_attachments=(local,)))
        self.assertEqual(result.status, "COMPLETED")
        self.assertEqual(len(client.calls), 1)
        evidence = result.canonical_request["enquiry"]["attachmentEvidence"][0]
        self.assertEqual(evidence["processingStatus"], "PRIVACY_VERIFIED")
        self.assertEqual(evidence["privacyTransformation"], "CONNECTOR_PIXEL_REDACTED")
        self.assertEqual(evidence["provenance"], "SENDER_PROVIDED")

    def test_external_thread_and_prior_issues_are_masked_and_preserved(self) -> None:
        result = MimePrivacyConnector(RecordingClient()).process(connector_input(permitted_thread=(ThreadMessage("external-secret-id", "STAFF", "Hello Alice Example"),), prior_issues=(PriorIssue("external-prior-id", "Alice Example needs an answer"),)))
        outbound = json.dumps(result.canonical_request)
        for raw in ("external-secret-id", "external-prior-id", "Alice Example"):
            self.assertNotIn(raw, outbound)
        self.assertEqual(result.canonical_request["enquiry"]["permittedThread"][0]["messageId"], "thread-001")
        self.assertEqual(result.canonical_request["enquiry"]["priorIssues"][0]["issueId"], "prior-001")

    def test_placeholder_maps_are_request_scoped(self) -> None:
        masker = SyntheticFixtureMasker()
        first, second = masker.new_session(), masker.new_session()
        token = first.mask("Alice Example").masked_text
        self.assertNotEqual(token, second.mask("Alice Example").masked_text)
        self.assertEqual(second.restore(token), token)
        self.assertEqual(first.restore(token), "Alice Example")

    def test_masking_failure_prevents_http_call(self) -> None:
        client = RecordingClient()
        result = MimePrivacyConnector(client, FailingMasker()).process(connector_input())
        self.assertEqual(result.failure.code, "MASKING_FAILURE")
        self.assertEqual(client.calls, [])

    def test_engine_unavailable_and_contract_rejected_are_typed(self) -> None:
        unavailable, rejected = RaisingClient(EngineUnavailableError()), RaisingClient(EngineContractRejectedError())
        self.assertEqual(MimePrivacyConnector(unavailable).process(connector_input()).failure.code, "ENGINE_UNAVAILABLE")
        self.assertEqual(MimePrivacyConnector(rejected).process(connector_input()).failure.code, "ENGINE_CONTRACT_REJECTED")
        self.assertTrue(unavailable.called and rejected.called)

    def test_all_local_bounds_fail_before_any_engine_call(self) -> None:
        long_subject = b"From: Alice Example <alice.synthetic@example.test>\nSubject: " + (b"s" * 1_001) + b"\n\nBody"
        cases = [
            connector_input(request_id="x" * 161),
            connector_input(correlation_id="bad\nidentifier"),
            connector_input(idempotency_key="bad\nkey"),
            connector_input(long_subject),
            connector_input(SYNTHETIC_EML.replace(b"Hello, my name", (b"x" * 40_001) + b" Hello, my name")),
            connector_input(permitted_thread=(ThreadMessage("thread", "STAFF", "x" * 20_001),)),
            connector_input(prior_issues=(PriorIssue("prior", "x" * 1_001),)),
            connector_input(prior_issues=(PriorIssue("prior", "ok", ("x" * 361,)),)),
            connector_input(externally_observed_attachments=(AttachmentMetadata("x" * 1_001, "application/pdf", None, "attachment"),)),
            connector_input(limits=ConnectorLimits(max_canonical_json_bytes=10)),
        ]
        for value in cases:
            with self.subTest(value=value.request_id):
                client = RecordingClient()
                result = MimePrivacyConnector(client).process(value)
                self.assertEqual(result.status, "REQUIRES_MANUAL_HANDLING")
                self.assertEqual(result.failure.code, "REQUEST_LIMIT_EXCEEDED" if not value.externally_observed_attachments else "ATTACHMENT_LIMIT_EXCEEDED")
                self.assertEqual(client.calls, [])

    def test_no_raw_logging_or_spool_is_created(self) -> None:
        calls: list[tuple] = []
        original = logging.Logger._log
        logging.Logger._log = lambda *args, **kwargs: calls.append(args)
        try:
            result = MimePrivacyConnector(RecordingClient()).process(connector_input())
        finally:
            logging.Logger._log = original
        self.assertEqual(result.status, "COMPLETED")
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
