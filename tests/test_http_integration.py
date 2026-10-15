"""Runs only when a local engine URL and a test key are provided in the environment."""

from __future__ import annotations

import json
import os
import unittest
from base64 import b64encode
from pathlib import Path

from io import BytesIO
from PIL import Image, ImageDraw, ImageFont

from pace_connector.client import LocalHttpEngineClient
from pace_connector.contracts import ConnectorInput, PriorIssue, ThreadMessage
from pace_connector.service import MimePrivacyConnector


def fixture_font() -> ImageFont.FreeTypeFont:
    for candidate in (
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    ):
        if Path(candidate).is_file():
            return ImageFont.truetype(candidate, 42)
    raise unittest.SkipTest("a system TrueType font is required for the deterministic OCR fixture")


@unittest.skipUnless(os.environ.get("PACE_CONNECTOR_ENGINE_URL") and os.environ.get("PACE_CONNECTOR_API_KEY"), "requires a running engine (PACE_CONNECTOR_ENGINE_URL, PACE_CONNECTOR_API_KEY)")
class EngineIntegrationTests(unittest.TestCase):
    def test_nq_r1_raw_mime_png_ocr_privacy_http_calibration(self) -> None:
        """Temporary non-scored calibration: image pixels are the sole marker source."""
        sentinel = "APPLICATION STATUS 8271"
        negative_sentinel = "NQ-NEGATIVE-HIDDEN"
        image = Image.new("RGB", (1800, 560), "white")
        draw = ImageDraw.Draw(image); font = fixture_font()
        draw.text((60, 90), "APPLICATION STATUS", fill="black", font=font)
        draw.text((60, 270), "8271", fill="black", font=font)
        attachment = BytesIO(); image.save(attachment, format="PNG")
        attachment_bytes = attachment.getvalue()
        encoded_attachment = b64encode(attachment_bytes)
        # Neither the subject nor the text/plain MIME part contains the
        # sentinel.  It exists only in the raster attachment pixels.
        raw = b"From: synthetic@example.test\r\nTo: pace@example.test\r\nSubject: Synthetic document enquiry\r\nMessage-ID: <nq-r1-calibration@example.test>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=nq-r1-boundary\r\n\r\n--nq-r1-boundary\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nPlease review the attached synthetic document.\r\n--nq-r1-boundary\r\nContent-Type: image/png\r\nContent-Disposition: attachment; filename=nq-document.png\r\nContent-Transfer-Encoding: base64\r\n\r\n" + encoded_attachment + b"\r\n--nq-r1-boundary--\r\n"
        self.assertNotIn(sentinel.encode(), raw)
        self.assertNotIn(negative_sentinel.encode(), raw)
        self.assertEqual(raw.count(attachment_bytes), 0, "MIME must carry the exact image only as encoded attachment bytes")
        connector = MimePrivacyConnector(LocalHttpEngineClient(os.environ["PACE_CONNECTOR_ENGINE_URL"], os.environ["PACE_CONNECTOR_API_KEY"]))
        result = connector.process(ConnectorInput(
            raw_eml=raw,
            request_id="rstn_req_0000000000000000000000000000ca11",
            correlation_id="rstn_cor_0000000000000000000000000000ca11",
            idempotency_key="rstn_idem_0000000000000000000000000000ca11",
        ))
        self.assertEqual(result.status, "COMPLETED", msg=str(result.failure))
        attachment_evidence = result.canonical_request["enquiry"]["attachmentEvidence"]
        self.assertEqual(len(attachment_evidence), 1)
        self.assertEqual(attachment_evidence[0]["provenance"], "SENDER_PROVIDED")
        self.assertEqual(attachment_evidence[0]["processingStatus"], "PRIVACY_VERIFIED")
        self.assertEqual(attachment_evidence[0]["contentState"], "METADATA_ONLY")
        self.assertEqual(attachment_evidence[0]["extractionMethod"], "OCR")
        self.assertIn("APPLICATION STATUS", attachment_evidence[0]["excerpt"])
        self.assertIn("8271", attachment_evidence[0]["excerpt"])
        outbound = json.dumps(result.canonical_request)
        safe_trace = json.dumps(result.engine_result["result"]["safeTrace"])
        self.assertNotIn("nq-document.png", outbound)
        self.assertNotIn(b64encode(attachment_bytes).decode(), outbound)
        self.assertNotIn("nq-document.png", safe_trace)
        self.assertNotIn("Payment has been recorded as received", json.dumps(result.engine_result["result"]))

        # Negative companion: one readable-looking pixel token cannot pass the
        # two-pass qualified OCR/privacy gate, so it cannot reach Headless.
        unreadable = Image.new("RGB", (300, 110), "white")
        ImageDraw.Draw(unreadable).text((15, 30), negative_sentinel, fill="black", font=font)
        unreadable_bytes = BytesIO(); unreadable.save(unreadable_bytes, format="PNG")
        negative_raw = raw.replace(encoded_attachment, b64encode(unreadable_bytes.getvalue()))
        negative = connector.process(ConnectorInput(
            raw_eml=negative_raw,
            request_id="rstn_req_0000000000000000000000000000ca12",
            correlation_id="rstn_cor_0000000000000000000000000000ca12",
            idempotency_key="rstn_idem_0000000000000000000000000000ca12",
        ))
        self.assertEqual(negative.status, "COMPLETED", msg=str(negative.failure))
        negative_evidence = negative.canonical_request["enquiry"]["attachmentEvidence"][0]
        self.assertNotEqual(negative_evidence["processingStatus"], "PRIVACY_VERIFIED")
        self.assertEqual(negative_evidence["contentState"], "NOT_READ")
        self.assertNotIn(negative_sentinel, json.dumps(negative.canonical_request))

    def test_real_local_chain_never_forwards_raw_synthetic_pii(self) -> None:
        image = Image.new("RGB", (1400, 460), "white")
        draw = ImageDraw.Draw(image); font = fixture_font()
        for index, line in enumerate(("Alice Example", "alice.synthetic@example.test", "+65 8123 4567", "Reference SYN-RECEIPT-001", "Payment completed")):
            draw.text((40, 30 + index * 80), line, fill="black", font=font)
        attachment_bytes = BytesIO(); image.save(attachment_bytes, format="PNG")
        encoded_attachment = b64encode(attachment_bytes.getvalue())
        raw = b"From: Alice Example <alice.synthetic@example.test>\nTo: pace@example.test\nSubject: Intake and payment\nMessage-ID: <synthetic-001@example.test>\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=mail-boundary\n\n--mail-boundary\nContent-Type: text/plain; charset=utf-8\n\nHello, my name is Alice Example.\nMy synthetic phone number is +65 8123 4567.\n\nWhat is the intake status for the Advanced Professional Certificate in Data Science and AI?\n\nI have also attached my payment receipt. Can you confirm that payment has been received?\n--mail-boundary\nContent-Type: image/png\nContent-Disposition: attachment; filename=alice-receipt.png\nContent-Transfer-Encoding: base64\n\n" + encoded_attachment + b"\n--mail-boundary--\n"
        connector = MimePrivacyConnector(LocalHttpEngineClient(os.environ["PACE_CONNECTOR_ENGINE_URL"], os.environ["PACE_CONNECTOR_API_KEY"]))
        result = connector.process(ConnectorInput(
            raw_eml=raw,
            request_id="rstn_req_0000000000000000000000000000aa01",
            correlation_id="rstn_cor_0000000000000000000000000000aa01",
            idempotency_key="rstn_idem_0000000000000000000000000000aa01",
            permitted_thread=(ThreadMessage("local-thread-id", "STAFF", "Please clarify your original question."),),
            prior_issues=(PriorIssue("local-prior-id", "Earlier question from Alice Example"),),
        ))
        self.assertEqual(result.status, "COMPLETED", msg=str(result.failure))
        outbound = json.dumps(result.canonical_request)
        safe_trace = json.dumps(result.engine_result["result"]["safeTrace"])
        for raw_value in ("Alice Example", "alice.synthetic@example.test", "+65 8123 4567", "pace@example.test"):
            self.assertNotIn(raw_value, outbound)
            self.assertNotIn(raw_value, safe_trace)
        self.assertEqual(result.engine_result["result"]["threadDelta"]["status"], "VALID")
        issues = result.engine_result["result"]["issues"]
        self.assertTrue(any(issue["recommendedAction"] == "ANSWER" for issue in issues))
        self.assertTrue(any(issue["recommendedAction"] == "MANUAL_REVIEW" for issue in issues))
        attachment_evidence = result.canonical_request["enquiry"]["attachmentEvidence"]
        self.assertEqual(attachment_evidence[0]["provenance"], "SENDER_PROVIDED")
        # Zero-token post-redaction OCR is intentionally not certified; the
        # receipt remains sender-provided metadata and its text stays local.
        self.assertEqual(attachment_evidence[0]["processingStatus"], "PRIVACY_UNCERTAIN")
        self.assertEqual(attachment_evidence[0]["contentState"], "NOT_READ")
        self.assertNotIn("alice-receipt.png", outbound)
        self.assertNotIn("alice-receipt.png", safe_trace)
        self.assertIsNotNone(result.restored_reply)

        # Paired semantic regression: remove sender PII locally but retain the
        # programme/payment questions and the same sender-provided receipt.
        baseline_raw = raw.replace(b"Hello, my name is Alice Example.\nMy synthetic phone number is +65 8123 4567.\n\n", b"Hello.\n\n")
        baseline = connector.process(ConnectorInput(
            raw_eml=baseline_raw,
            request_id="rstn_req_0000000000000000000000000000aa02",
            correlation_id="rstn_cor_0000000000000000000000000000aa02",
            idempotency_key="rstn_idem_0000000000000000000000000000aa02",
            permitted_thread=(ThreadMessage("local-thread-id", "STAFF", "Please clarify your original question."),),
            prior_issues=(PriorIssue("local-prior-id", "Earlier question"),),
        ))
        self.assertEqual(baseline.status, "COMPLETED")
        summary = lambda value: [(item["issueId"], item["answerability"], item["recommendedAction"]) for item in value.engine_result["result"]["issues"]]
        self.assertEqual(summary(result), summary(baseline))

    def test_masked_semantics_match_pii_removed_controls_across_multiple_enquiry_types(self) -> None:
        client = LocalHttpEngineClient(os.environ["PACE_CONNECTOR_ENGINE_URL"], os.environ["PACE_CONNECTOR_API_KEY"])
        cases = (
            ("intake", b"Dr Jane Doe asks about the August intake for the Advanced Professional Certificate in Data Science and AI."),
            ("ownership", b"Dr Jane Doe asks which office owns routing for a programme application."),
            ("multi-issue", b"Dr Jane Doe asks about programme intake and whether a payment receipt needs manual review."),
            ("follow-up", b"Dr Jane Doe follows up on an earlier programme application question."),
            ("payment", b"Dr Jane Doe asks whether sender-provided payment evidence can be confirmed."),
        )
        summary = lambda value: [(item["issueId"], item["answerability"], item["recommendedAction"]) for item in value.engine_result["result"]["issues"]]
        for index, (label, body) in enumerate(cases, start=1):
            with self.subTest(case=label):
                raw = b"From: Dr Jane Doe <jane.doe@example.test>\nSubject: Programme enquiry\n\n" + body + b" Contact jane.doe@example.test or +65 8123 4567."
                control = raw.replace(b"Dr Jane Doe ", b"").replace(b" Contact jane.doe@example.test or +65 8123 4567.", b"")
                masked = MimePrivacyConnector(client).process(ConnectorInput(raw, f"rstn_req_{index:032x}", f"rstn_cor_{index:032x}", f"rstn_idem_{index:032x}"))
                baseline = MimePrivacyConnector(client).process(ConnectorInput(control, f"rstn_req_{index + 16:032x}", f"rstn_cor_{index + 16:032x}", f"rstn_idem_{index + 16:032x}"))
                self.assertEqual(masked.status, "COMPLETED")
                self.assertEqual(baseline.status, "COMPLETED")
                self.assertEqual(summary(masked), summary(baseline))


if __name__ == "__main__":
    unittest.main()
