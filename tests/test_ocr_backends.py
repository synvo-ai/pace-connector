from __future__ import annotations

import importlib.util
import unittest
from io import BytesIO
from pathlib import Path

from PIL import Image

from pace_connector.attachments import LocalAttachmentProcessor, PaddleOcrEngine
from pace_connector.contracts import AttachmentMetadata, LocalAttachment
from pace_connector.privacy import SyntheticFixturePrivacyDetector


class _EmptyPaddle:
    def predict(self, _image): return []


class _FailingPaddle:
    def predict(self, _image): raise RuntimeError("synthetic failure")


class _UnicodePaddle:
    def predict(self, _image):
        return [{
            "rec_texts": ["Ålice 示例"],
            "rec_polys": [[[0, 0], [10, 0], [10, 5], [0, 5]]],
            "rec_scores": [.75],
        }]


# The real-Paddle tests need the optional extra: pip install -e ".[paddle]".
_requires_paddle = unittest.skipUnless(importlib.util.find_spec("paddleocr"), "PaddleOCR is an optional extra")


class PaddleAdapterTests(unittest.TestCase):
    def test_empty_result_is_an_empty_token_list(self) -> None:
        engine = object.__new__(PaddleOcrEngine); engine._ocr = _EmptyPaddle()
        self.assertEqual(engine.read(Image.new("RGB", (10, 10), "white")), [])

    def test_exception_is_explicit(self) -> None:
        engine = object.__new__(PaddleOcrEngine); engine._ocr = _FailingPaddle()
        with self.assertRaisesRegex(RuntimeError, "execution failed"):
            engine.read(Image.new("RGB", (10, 10), "white"))

    def test_unicode_confidence_page_and_polygon_are_normalised(self) -> None:
        engine = object.__new__(PaddleOcrEngine); engine._ocr = _UnicodePaddle()
        token = engine.read(Image.new("RGB", (20, 10), "white"))[0]
        self.assertEqual((token.text, token.page, token.confidence), ("Ålice 示例", 0, .75))
        self.assertEqual(token.polygon, ((0.0, 0.0), (.5, 0.0), (.5, .5), (0.0, .5)))

    @_requires_paddle
    def test_real_adapter_returns_normalised_unicode_tokens(self) -> None:
        engine = PaddleOcrEngine()
        image = Image.new("RGB", (600, 160), "white")
        from PIL import ImageDraw, ImageFont
        for candidate in ("/System/Library/Fonts/Supplemental/Arial.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/dejavu/DejaVuSans.ttf"):
            if Path(candidate).is_file():
                image_font = ImageFont.truetype(candidate, 42)
                break
        else:
            self.skipTest("a system TrueType font is required for this OCR fixture")
        ImageDraw.Draw(image).text((20, 40), "Alice Example", fill="black", font=image_font)
        tokens = engine.read(image)
        self.assertTrue(tokens)
        self.assertTrue(all(isinstance(token.text, str) and token.page == 0 and 0 <= token.confidence <= 1 for token in tokens))
        self.assertTrue(all(0 <= x <= 1 and 0 <= y <= 1 for token in tokens for x, y in token.polygon))

    @_requires_paddle
    def test_existing_privacy_pipeline_accepts_paddle_tokens_without_contract_changes(self) -> None:
        image = Image.new("RGB", (900, 360), "white")
        from PIL import ImageDraw, ImageFont
        for candidate in ("/System/Library/Fonts/Supplemental/Arial.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/dejavu/DejaVuSans.ttf"):
            if Path(candidate).is_file():
                image_font = ImageFont.truetype(candidate, 36)
                break
        else:
            self.skipTest("a system TrueType font is required for this OCR fixture")
        draw = ImageDraw.Draw(image)
        for index, value in enumerate(("Alice Example", "alice.synthetic@example.test", "+65 8123 4567", "SYN-RECEIPT-001")):
            draw.text((25, 20 + index * 80), value, fill="black", font=image_font)
        content = BytesIO(); image.save(content, format="PNG")
        result = LocalAttachmentProcessor(ocr_engine=PaddleOcrEngine(), detector=SyntheticFixturePrivacyDetector()).process(LocalAttachment(
            AttachmentMetadata("synthetic.png", "image/png", len(content.getvalue()), "attachment"), content.getvalue(),
        ))
        # A fully blacked-out receipt can produce zero verification tokens;
        # The connector treats that ambiguity as fail-closed rather than verified.
        self.assertEqual(result.status, "PRIVACY_UNCERTAIN")
        self.assertFalse(result.raw_text_local_only)


if __name__ == "__main__": unittest.main()
