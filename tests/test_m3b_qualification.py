"""Held-out synthetic privacy gate; no corpus contents are emitted as telemetry."""

from __future__ import annotations

from io import BytesIO
from pathlib import Path
import unittest

from PIL import Image, ImageDraw, ImageFont

from pdf_fixtures import image_pdf, text_pdf
from pace_connector.attachments import LocalAttachmentProcessor
from pace_connector.contracts import AttachmentMetadata, LocalAttachment
from pace_connector.masking import LocalPrivacyMasker
from pace_connector.privacy import EgressPrivacyGate, LocalPrivacyDetector


HELD_OUT = (
    ("PERSON", "Professor Maria-Louise Tan asks about an intake."),
    ("EMAIL", "Please reply to maria.tan @ applicant.example.test."),
    ("PHONE", "Telephone: +65-8123-4567."),
    ("NRIC_FIN", "Synthetic fixture FIN T0123456Z."),
    ("REFERENCE", "Application: APP-2026-001."),
    ("SYNTHETIC_ID", "Reference SYN-HOLDOUT-901."),
)


def _font(size: int):
    for candidate in ("/System/Library/Fonts/Supplemental/Arial.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/dejavu/DejaVuSans.ttf"):
        if Path(candidate).is_file(): return ImageFont.truetype(candidate, size)
    raise unittest.SkipTest("a system TrueType font is required for deterministic OCR fixtures")


def _receipt_image() -> Image.Image:
    image = Image.new("RGB", (1300, 520), "white"); draw = ImageDraw.Draw(image); font = _font(38)
    for index, value in enumerate(("Dr Jane Doe", "jane.doe@example.test", "+65 8123 4567", "S1234567A", "Reference REF-CASE-001")):
        draw.text((25, 20 + index * 95), value, font=font, fill="black")
    return image


class M3BQualificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.detector = LocalPrivacyDetector(); cls.gate = EgressPrivacyGate()

    def test_held_out_text_corpus_has_zero_outbound_leaks_and_preserves_negative_business_controls(self) -> None:
        session = LocalPrivacyMasker(self.detector).new_session()
        detected = masked = 0
        for category, source in HELD_OUT:
            findings = self.detector.find(source)
            self.assertIn(category, {finding.category for finding in findings})
            detected += 1
            outbound = session.mask(source).masked_text
            for finding in findings:
                self.assertNotIn(source[finding.start:finding.end], outbound)
            self.gate.validate({"enquiry": {"currentMessage": {"subject": "Programme enquiry", "body": outbound}, "permittedThread": [], "priorIssues": [], "attachmentEvidence": []}})
            masked += 1
        self.assertEqual((detected, masked), (len(HELD_OUT), len(HELD_OUT)))
        public = "NTU PaCE Advanced Professional Certificate in Data Science and AI begins on 1 May 2026 and costs $1200."
        self.assertEqual(self.detector.find(public), ())
        self.assertEqual(session.mask(public).masked_text, public)

    def test_general_detector_keeps_attachment_text_local_when_verification_is_uncertain(self) -> None:
        processor = LocalAttachmentProcessor(detector=self.detector)
        image = _receipt_image(); raster = BytesIO(); image.save(raster, format="PNG")
        png = LocalAttachment(AttachmentMetadata("synthetic.png", "image/png", len(raster.getvalue()), "attachment"), raster.getvalue())
        scanned = image_pdf(650, 260, raster.getvalue())
        native = text_pdf(650, 260, [(20, 35 + index * 40, value, 18) for index, value in enumerate(("Dr Jane Doe", "jane.doe@example.test +65 8123 4567", "S1234567A Reference REF-CASE-001"))])
        attachments = (
            png,
            LocalAttachment(AttachmentMetadata("scanned.pdf", "application/pdf", len(scanned), "attachment"), scanned),
            LocalAttachment(AttachmentMetadata("native.pdf", "application/pdf", len(native), "attachment"), native),
        )
        for attachment in attachments:
            with self.subTest(mime=attachment.metadata.mime_type):
                result = processor.process(attachment)
                self.assertEqual(result.status, "PRIVACY_UNCERTAIN")
                self.assertFalse(result.raw_text_local_only)


if __name__ == "__main__": unittest.main()
