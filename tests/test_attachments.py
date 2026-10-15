from __future__ import annotations

from io import BytesIO
from pathlib import Path
import unittest

from PIL import Image, ImageDraw, ImageFont

from pdf_fixtures import blank_pdf, encrypted_pdf, image_pdf, text_pdf
from pace_connector.attachments import AttachmentProcessingLimits, LocalAttachmentProcessor, OcrToken, SyntheticFixtureDetector, _align
from pace_connector.contracts import AttachmentMetadata, LocalAttachment
from pace_connector.privacy import LocalPrivacyDetector


def fixture_font(size: int) -> ImageFont.FreeTypeFont:
    for candidate in (
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    ):
        if Path(candidate).is_file():
            return ImageFont.truetype(candidate, size)
    raise unittest.SkipTest("a system TrueType font is required for the deterministic OCR fixture")


def receipt_image() -> Image.Image:
    image = Image.new("RGB", (1400, 620), "white")
    draw = ImageDraw.Draw(image)
    font = fixture_font(42)
    for index, line in enumerate(("Receipt", "Alice Example", "alice.synthetic@example.test", "+65 8123 4567", "Reference SYN-RECEIPT-001", "Payment completed")):
        draw.text((50, 35 + index * 90), line, fill="black", font=font)
    return image


def image_attachment(format: str = "PNG") -> LocalAttachment:
    output = BytesIO(); receipt_image().save(output, format=format)
    return LocalAttachment(AttachmentMetadata(f"receipt.{format.lower()}", f"image/{format.lower() if format != 'JPEG' else 'jpeg'}", len(output.getvalue()), "attachment"), output.getvalue())


def native_pdf() -> LocalAttachment:
    content = text_pdf(700, 500, [(50, 70, "Alice Example", 28), (50, 120, "alice.synthetic@example.test", 22), (50, 170, "+65 8123 4567 SYN-PDF-001", 22)])
    return LocalAttachment(AttachmentMetadata("receipt.pdf", "application/pdf", len(content), "attachment"), content)


def scanned_pdf() -> LocalAttachment:
    picture = BytesIO(); receipt_image().save(picture, format="PNG")
    content = image_pdf(700, 310, picture.getvalue())
    return LocalAttachment(AttachmentMetadata("scanned.pdf", "application/pdf", len(content), "attachment"), content)


class FailingOcr:
    def read(self, image): raise RuntimeError("fixture OCR failure")


class LowConfidenceOcr:
    def read(self, image): return [OcrToken("Alice", 0, ((.1,.1),(.2,.1),(.2,.2),(.1,.2)), .1), OcrToken("Example", 0, ((.21,.1),(.4,.1),(.4,.2),(.21,.2)), .1)]


class VerificationFailureOcr:
    def read(self, image): return [OcrToken("Alice Example", 0, ((.1,.1),(.4,.1),(.4,.2),(.1,.2)), 1.0)]


class AttachmentProcessingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # The failure-mode assertion must not vary with the locally cached OCR
        # model.  It explicitly supplies unusable verification OCR tokens.
        cls.processor = LocalAttachmentProcessor(ocr_engine=VerificationFailureOcr(), detector=SyntheticFixtureDetector())

    def test_real_png_jpeg_native_pdf_and_scanned_pdf_fail_closed_when_verification_returns_no_usable_text(self) -> None:
        for attachment in (image_attachment(), image_attachment("JPEG"), native_pdf(), scanned_pdf()):
            with self.subTest(mime=attachment.metadata.mime_type):
                result = self.processor.process(attachment)
                self.assertEqual(result.status, "PRIVACY_UNCERTAIN")
                self.assertFalse(result.metrics.verification_passed)

    def test_no_pii_image_without_verifiable_ocr_text_is_fail_closed(self) -> None:
        image = Image.new("RGB", (600, 200), "white"); ImageDraw.Draw(image).text((30, 50), "Public programme information", fill="black", font=fixture_font(36))
        output = BytesIO(); image.save(output, format="PNG")
        result = self.processor.process(LocalAttachment(AttachmentMetadata("public.png", "image/png", len(output.getvalue()), "attachment"), output.getvalue()))
        self.assertEqual(result.status, "PRIVACY_UNCERTAIN")

    def test_real_ocr_naturally_capitalised_controlled_programme_is_privacy_verified(self) -> None:
        # This runs the real local RapidOCR engine twice (initial extraction and
        # redaction verification), rather than supplying synthetic OCR tokens.
        image = Image.new("RGB", (1800, 500), "white")
        draw = ImageDraw.Draw(image); font = fixture_font(56)
        draw.text((40, 55), "Product Design Certificate", fill="black", font=font)
        draw.text((40, 220), "programme information", fill="black", font=font)
        output = BytesIO(); image.save(output, format="PNG")
        attachment = LocalAttachment(AttachmentMetadata("public-programme.png", "image/png", len(output.getvalue()), "attachment"), output.getvalue())
        result = LocalAttachmentProcessor(detector=LocalPrivacyDetector()).process(attachment)
        self.assertEqual(result.status, "PRIVACY_VERIFIED")
        self.assertEqual(result.extraction_method, "OCR")
        self.assertEqual(result.privacy_transformation, "CONNECTOR_MASKED")
        self.assertIn("Product Design Certificate", result.raw_text_local_only)

    def test_low_confidence_unmappable_ocr_and_verification_failure_fail_closed(self) -> None:
        attachment = image_attachment()
        low = LocalAttachmentProcessor(ocr_engine=LowConfidenceOcr(), detector=SyntheticFixtureDetector()).process(attachment)
        failed_verification = LocalAttachmentProcessor(ocr_engine=VerificationFailureOcr(), detector=SyntheticFixtureDetector()).process(attachment)
        self.assertEqual(low.status, "PRIVACY_UNCERTAIN")
        self.assertEqual(failed_verification.status, "PRIVACY_UNCERTAIN")

    def test_geometry_aligns_multi_token_name_and_split_phone_and_email(self) -> None:
        tokens = [
            OcrToken("Alice", 0, ((.02,.1),(.12,.1),(.12,.2),(.02,.2)), 1.0),
            OcrToken("Example", 0, ((.13,.1),(.28,.1),(.28,.2),(.13,.2)), 1.0),
            OcrToken("alice.synthetic", 0, ((.02,.3),(.28,.3),(.28,.4),(.02,.4)), 1.0),
            OcrToken("@example", 0, ((.29,.3),(.46,.3),(.46,.4),(.29,.4)), 1.0),
            OcrToken(".test", 0, ((.47,.3),(.56,.3),(.56,.4),(.47,.4)), 1.0),
            OcrToken("+65", 0, ((.02,.5),(.09,.5),(.09,.6),(.02,.6)), 1.0),
            OcrToken("8123", 0, ((.1,.5),(.2,.5),(.2,.6),(.1,.6)), 1.0),
            OcrToken("4567", 0, ((.21,.5),(.31,.5),(.31,.6),(.21,.6)), 1.0),
        ]
        joined = " ".join(token.text for token in tokens)
        regions = _align(SyntheticFixtureDetector().spans(joined), tokens, .5)
        self.assertEqual(len(regions), 3)
        self.assertTrue(all(0 <= left < right <= 1 and 0 <= top < bottom <= 1 for left, top, right, bottom in regions))

    def test_malformed_encrypted_unsupported_oversized_pages_and_ocr_failure_are_explicit(self) -> None:
        malformed = LocalAttachment(AttachmentMetadata("bad.pdf", "application/pdf", 3, "attachment"), b"bad")
        unsupported = LocalAttachment(AttachmentMetadata("file.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", 3, "attachment"), b"bad")
        oversized = LocalAttachmentProcessor(AttachmentProcessingLimits(max_attachment_bytes=1), detector=SyntheticFixtureDetector()).process(image_attachment())
        ocr_failure = LocalAttachmentProcessor(ocr_engine=FailingOcr(), detector=SyntheticFixtureDetector()).process(image_attachment())
        encrypted_bytes = encrypted_pdf()
        encrypted = LocalAttachment(AttachmentMetadata("encrypted.pdf", "application/pdf", len(encrypted_bytes), "attachment"), encrypted_bytes)
        many_bytes = blank_pdf(2)
        page_limited = LocalAttachmentProcessor(AttachmentProcessingLimits(max_pdf_pages=1), detector=SyntheticFixtureDetector()).process(LocalAttachment(AttachmentMetadata("many.pdf", "application/pdf", len(many_bytes), "attachment"), many_bytes))
        self.assertEqual(self.processor.process(malformed).status, "EXTRACTION_FAILED")
        self.assertEqual(self.processor.process(unsupported).status, "UNSUPPORTED")
        self.assertEqual(oversized.status, "EXTRACTION_FAILED")
        self.assertEqual(ocr_failure.status, "OCR_FAILED")
        self.assertEqual(self.processor.process(encrypted).status, "EXTRACTION_FAILED")
        self.assertEqual(page_limited.status, "EXTRACTION_FAILED")


if __name__ == "__main__": unittest.main()
