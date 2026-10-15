"""Local-only attachment extraction, OCR, pixel redaction and verification."""

from __future__ import annotations

from dataclasses import dataclass, field
from io import BytesIO
import re
import time
from typing import Literal, Protocol

from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, UnidentifiedImageError
import pypdfium2

from .contracts import LocalAttachment
from .privacy import EgressPrivacySentinel, PrivacyDetector, SyntheticFixturePrivacyDetector

AttachmentProcessingStatus = Literal[
    "NOT_READ", "UNSUPPORTED", "EXTRACTION_FAILED", "OCR_FAILED",
    "PRIVACY_DETECTION_FAILED", "PRIVACY_SCOPE_UNSUPPORTED", "PRIVACY_UNCERTAIN", "REDACTION_FAILED", "REDACTION_VERIFICATION_FAILED", "PRIVACY_VERIFIED",
]


@dataclass(frozen=True)
class OcrToken:
    text: str
    page: int
    polygon: tuple[tuple[float, float], ...]  # normalised [0,1] coordinates
    confidence: float


@dataclass(frozen=True)
class AttachmentMetrics:
    file_type: str
    page_count: int
    pixels_processed: int
    ocr_token_count: int
    ocr_duration_ms: int
    redaction_duration_ms: int
    verification_passed: bool
    processing_status: AttachmentProcessingStatus


@dataclass(frozen=True)
class AttachmentProcessingResult:
    status: AttachmentProcessingStatus
    extraction_method: Literal["PDF_TEXT", "OCR", "NONE"]
    privacy_transformation: Literal["NONE", "CONNECTOR_MASKED", "CONNECTOR_PIXEL_REDACTED"]
    raw_text_local_only: str
    source_regions: tuple[tuple[int, tuple[float, float, float, float]], ...]
    redacted_pages_local_only: tuple[bytes, ...]
    metrics: AttachmentMetrics


@dataclass(frozen=True)
class AttachmentProcessingLimits:
    max_attachment_bytes: int = 8 * 1024 * 1024
    max_attachments: int = 24
    max_pdf_pages: int = 10
    max_image_width: int = 4_000
    max_image_height: int = 4_000
    max_total_rendered_pixels: int = 16_000_000
    max_ocr_pages: int = 10
    max_elapsed_seconds: float = 12.0
    min_alignment_confidence: float = 0.50
    # A nontrivial raster/scanned page with no or a lone OCR token cannot be
    # distinguished safely from an OCR miss; do not certify it as private.
    min_usable_tokens_per_page: int = 2


class OcrEngine(Protocol):
    def read(self, image: Image.Image) -> list[OcrToken]: ...


class RapidOcrEngine:
    """CPU-only RapidOCR (ONNX Runtime) with the PP-OCRv5 mobile detector and English recogniser.

    The model files ship inside the package (`pace_connector/models`), so nothing is downloaded
    at run time. Chosen on 15 Oct 2026 over the PP-OCRv4 models: about 98% of words read instead
    of 89%, at the same speed and memory on CPU.
    """

    def __init__(self) -> None:
        from rapidocr import LangDet, LangRec, ModelType, OCRVersion, RapidOCR

        models = Path(__file__).with_name("models")
        self._ocr = RapidOCR(params={
            "Global.log_level": "error",
            "Det.ocr_version": OCRVersion.PPOCRV5, "Det.model_type": ModelType.MOBILE, "Det.lang_type": LangDet.MULTI,
            "Det.model_path": str(models / "ch_PP-OCRv5_det_mobile.onnx"),
            "Rec.ocr_version": OCRVersion.PPOCRV5, "Rec.model_type": ModelType.MOBILE, "Rec.lang_type": LangRec.EN,
            "Rec.model_path": str(models / "en_PP-OCRv5_rec_mobile.onnx"),
            "Cls.model_path": str(models / "ch_ppocr_mobile_v2.0_cls_mobile.onnx"),
        })

    def read(self, image: Image.Image) -> list[OcrToken]:
        output = self._ocr(np.array(image.convert("RGB")))
        if output.boxes is None:
            return []
        width, height = image.size
        tokens: list[OcrToken] = []
        for polygon, text, confidence in zip(output.boxes, output.txts, output.scores):
            normalised = tuple((max(0.0, min(1.0, float(x) / width)), max(0.0, min(1.0, float(y) / height))) for x, y in polygon)
            tokens.append(OcrToken(str(text), 0, normalised, float(confidence)))
        return tokens


class PaddleOcrEngine:
    """Optional local PaddleOCR adapter; no Paddle result crosses this boundary."""

    def __init__(self) -> None:
        try:
            from paddleocr import PaddleOCR
        except ImportError as error:
            raise RuntimeError("PaddleOCR is optional; install pace-connector[paddle].") from error
        # Preserve input coordinate space. Rotation/unwarping is deliberately
        # disabled so recognition polygons can be normalised against `image`.
        self._ocr = PaddleOCR(
            lang="en",
            use_doc_orientation_classify=False,
            use_doc_unwarping=False,
            use_textline_orientation=False,
        )

    def read(self, image: Image.Image) -> list[OcrToken]:
        try:
            pages = list(self._ocr.predict(np.array(image.convert("RGB"))))
        except Exception as error:
            raise RuntimeError("PaddleOCR execution failed") from error
        if not pages:
            return []
        width, height = image.size
        tokens: list[OcrToken] = []
        try:
            for page in pages:
                texts = page["rec_texts"]
                polygons = page["rec_polys"]
                confidences = page["rec_scores"]
                if not (len(texts) == len(polygons) == len(confidences)):
                    raise ValueError("PaddleOCR result lengths disagree")
                for text, polygon, confidence in zip(texts, polygons, confidences):
                    value = str(text)
                    if not value.strip():
                        continue
                    normalised = tuple(
                        (max(0.0, min(1.0, float(x) / width)), max(0.0, min(1.0, float(y) / height)))
                        for x, y in polygon
                    )
                    if len(normalised) < 4:
                        raise ValueError("PaddleOCR polygon is incomplete")
                    tokens.append(OcrToken(value, 0, normalised, float(confidence)))
        except (KeyError, TypeError, ValueError, IndexError) as error:
            raise RuntimeError("PaddleOCR returned an unsupported result") from error
        return tokens


class SyntheticFixtureDetector:
    """Test-only detector shared in spirit with the synthetic masker; not production PII detection."""

    patterns = (
        # OCR commonly separates punctuation into neighbouring tokens; permit
        # only inter-token whitespace around the fixed synthetic email domain.
        re.compile(r"\b[a-z0-9._%+-]+\s*@\s*example\s*\.\s*test\b", re.IGNORECASE),
        re.compile(r"\+65\s?\d{4}\s?\d{4}\b"),
        re.compile(r"\b(?:Alice|Bob|Carol) Example\b"),
        re.compile(r"\bSYN-[A-Z0-9-]{4,}\b"),
    )

    def spans(self, text: str) -> list[tuple[int, int]]:
        return [(match.start(), match.end()) for pattern in self.patterns for match in pattern.finditer(text)]

    def find(self, text: str):
        return SyntheticFixturePrivacyDetector().find(text)


class _AttachmentFailure(Exception):
    def __init__(self, status: AttachmentProcessingStatus) -> None: self.status = status


class LocalAttachmentProcessor:
    def __init__(self, limits: AttachmentProcessingLimits | None = None, ocr_engine: OcrEngine | None = None, detector: PrivacyDetector | None = None) -> None:
        self.limits = limits or AttachmentProcessingLimits()
        self.ocr = ocr_engine or RapidOcrEngine()
        # Production processing must choose a real detector explicitly. Tests
        # that need fixture semantics inject SyntheticFixtureDetector directly.
        if detector is None:
            raise ValueError("LocalAttachmentProcessor requires an explicit privacy detector")
        self.detector = detector
        self._verification_sentinel = EgressPrivacySentinel()

    def process(self, attachment: LocalAttachment) -> AttachmentProcessingResult:
        started = time.monotonic()
        file_type = attachment.metadata.mime_type.lower()
        try:
            if len(attachment.content) > self.limits.max_attachment_bytes:
                raise _AttachmentFailure("EXTRACTION_FAILED")
            if file_type == "application/pdf" or attachment.content.startswith(b"%PDF-"):
                pages, text_tokens, method, ocr_duration_ms = self._pdf_pages(attachment.content, started)
            elif file_type in {"image/png", "image/jpeg", "image/jpg"}:
                pages, text_tokens, method, ocr_duration_ms = self._image_pages(attachment.content, started)
            else:
                raise _AttachmentFailure("UNSUPPORTED")
            raw_text, regions, redacted, metrics = self._privacy_pipeline(pages, text_tokens, method, file_type, started, ocr_duration_ms)
            return AttachmentProcessingResult("PRIVACY_VERIFIED", method, "CONNECTOR_PIXEL_REDACTED" if regions else "CONNECTOR_MASKED", raw_text, tuple(regions), tuple(redacted), metrics)
        except _AttachmentFailure as error:
            return _failed(error.status, file_type)
        except pypdfium2.PdfiumError:
            return _failed("EXTRACTION_FAILED", file_type)
        except (UnidentifiedImageError, OSError, ValueError):
            return _failed("EXTRACTION_FAILED", file_type)

    def _pdf_pages(self, content: bytes, started: float):
        try:
            # A password-protected PDF fails to open, like any unreadable PDF.
            document = pypdfium2.PdfDocument(content)
        except Exception as error:
            raise _AttachmentFailure("EXTRACTION_FAILED") from error
        try:
            if len(document) > self.limits.max_pdf_pages or len(document) > self.limits.max_ocr_pages:
                raise _AttachmentFailure("EXTRACTION_FAILED")
            pages: list[Image.Image] = []
            token_pages: list[list[OcrToken]] = []
            ocr_duration_ms = 0
            method: Literal["PDF_TEXT", "OCR"] = "PDF_TEXT"
            for number in range(len(document)):
                self._check_time(started)
                page = document[number]
                image = page.render(scale=2).to_pil().convert("RGB")
                self._validate_pixels([*pages, image])
                words = _pdf_words(page, number)
                if words:
                    token_pages.append(words)
                else:
                    method = "OCR"
                    ocr_started = time.monotonic()
                    token_pages.append(self._ocr_page(image, number, started))
                    ocr_duration_ms += int((time.monotonic() - ocr_started) * 1000)
                pages.append(image)
            return pages, token_pages, method, ocr_duration_ms
        finally:
            document.close()

    def _image_pages(self, content: bytes, started: float):
        try:
            image = Image.open(BytesIO(content))
            image.load()
            if image.format not in {"PNG", "JPEG"}:
                raise _AttachmentFailure("UNSUPPORTED")
            image = image.convert("RGB")
        except _AttachmentFailure:
            raise
        except Exception as error:
            raise _AttachmentFailure("EXTRACTION_FAILED") from error
        self._validate_pixels([image])
        ocr_started = time.monotonic()
        tokens = self._ocr_page(image, 0, started)
        return [image], [tokens], "OCR", int((time.monotonic() - ocr_started) * 1000)

    def _ocr_page(self, image: Image.Image, page: int, started: float) -> list[OcrToken]:
        self._check_time(started)
        try:
            return [OcrToken(token.text, page, token.polygon, token.confidence) for token in self.ocr.read(image)]
        except Exception as error:
            raise _AttachmentFailure("OCR_FAILED") from error

    def _privacy_pipeline(self, pages, token_pages, method, file_type, started, initial_ocr_duration_ms):
        all_text: list[str] = []
        regions: list[tuple[int, tuple[float, float, float, float]]] = []
        redacted: list[bytes] = []
        ocr_tokens = sum(len(tokens) for tokens in token_pages)
        verification_ocr_duration_ms = 0
        redaction_duration_ms = 0
        for page_number, (image, tokens) in enumerate(zip(pages, token_pages)):
            if len(tokens) < self.limits.min_usable_tokens_per_page:
                raise _AttachmentFailure("PRIVACY_UNCERTAIN")
            joined = " ".join(token.text for token in tokens)
            all_text.append(joined)
            try:
                findings = self.detector.find(joined)
            except Exception as error:
                name = type(error).__name__
                raise _AttachmentFailure("PRIVACY_SCOPE_UNSUPPORTED" if name == "PrivacyScopeUnsupportedError" else "PRIVACY_DETECTION_FAILED") from error
            matches = [(finding.start, finding.end) for finding in findings]
            if tokens and sum(token.confidence for token in tokens) / len(tokens) < self.limits.min_alignment_confidence:
                raise _AttachmentFailure("PRIVACY_UNCERTAIN")
            aligned = _align(matches, tokens, self.limits.min_alignment_confidence)
            if matches and not aligned:
                raise _AttachmentFailure("PRIVACY_DETECTION_FAILED")
            regions.extend((page_number, region) for region in aligned)
            try:
                redaction_started = time.monotonic()
                redacted_image = _redact(image, aligned)
                output = BytesIO()
                redacted_image.save(output, format="PNG")
                redaction_duration_ms += int((time.monotonic() - redaction_started) * 1000)
            except Exception as error:
                raise _AttachmentFailure("REDACTION_FAILED") from error
            # Independent real OCR on the resulting pixels is the verification gate.
            verification_started = time.monotonic()
            verified_tokens = self._ocr_page(redacted_image, page_number, started)
            verification_ocr_duration_ms += int((time.monotonic() - verification_started) * 1000)
            if len(verified_tokens) < self.limits.min_usable_tokens_per_page:
                raise _AttachmentFailure("PRIVACY_UNCERTAIN")
            try:
                verified_text = " ".join(token.text for token in verified_tokens)
                residual = self.detector.find(verified_text)
            except Exception as error:
                name = type(error).__name__
                raise _AttachmentFailure("PRIVACY_SCOPE_UNSUPPORTED" if name == "PrivacyScopeUnsupportedError" else "PRIVACY_DETECTION_FAILED") from error
            if residual:
                raise _AttachmentFailure("REDACTION_VERIFICATION_FAILED")
            # The primary detector produced the redaction plan; independent
            # structural/person sentinel confirms no residual is OCR-visible.
            if self._verification_sentinel.scan_text(verified_text):
                raise _AttachmentFailure("REDACTION_VERIFICATION_FAILED")
            redacted.append(output.getvalue())
        metrics = AttachmentMetrics(file_type, len(pages), sum(image.width * image.height for image in pages), ocr_tokens, initial_ocr_duration_ms + verification_ocr_duration_ms, redaction_duration_ms, True, "PRIVACY_VERIFIED")
        return "\n".join(all_text), regions, redacted, metrics

    def _validate_pixels(self, pages: list[Image.Image]) -> None:
        for image in pages:
            if image.width > self.limits.max_image_width or image.height > self.limits.max_image_height:
                raise _AttachmentFailure("EXTRACTION_FAILED")
        if sum(image.width * image.height for image in pages) > self.limits.max_total_rendered_pixels:
            raise _AttachmentFailure("EXTRACTION_FAILED")

    def _check_time(self, started: float) -> None:
        if time.monotonic() - started > self.limits.max_elapsed_seconds:
            raise _AttachmentFailure("OCR_FAILED")


def _pdf_words(page, number: int) -> list[OcrToken]:
    """Embedded PDF text as words with page-relative boxes (top-left origin)."""
    width, height = page.get_size()
    textpage = page.get_textpage()
    try:
        words: list[OcrToken] = []
        text, boxes = "", []
        def flush() -> None:
            if text.strip():
                left, right = min(box[0] for box in boxes), max(box[2] for box in boxes)
                bottom, top = min(box[1] for box in boxes), max(box[3] for box in boxes)
                x0, x1 = max(0.0, left / width), min(1.0, right / width)
                y0, y1 = max(0.0, (height - top) / height), min(1.0, (height - bottom) / height)
                words.append(OcrToken(text, number, ((x0, y0), (x1, y0), (x1, y1), (x0, y1)), 1.0))
        for index in range(textpage.count_chars()):
            character = textpage.get_text_range(index, 1)
            if not character or character.isspace() or character == "\x00":
                flush()
                text, boxes = "", []
                continue
            text += character
            boxes.append(textpage.get_charbox(index))
        flush()
        return words
    finally:
        textpage.close()


def _align(matches: list[tuple[int, int]], tokens: list[OcrToken], minimum_confidence: float) -> list[tuple[float, float, float, float]]:
    if not matches:
        return []
    ranges: list[tuple[int, int, OcrToken]] = []
    position = 0
    for token in tokens:
        ranges.append((position, position + len(token.text), token))
        position += len(token.text) + 1
    regions: list[tuple[float, float, float, float]] = []
    for start, end in matches:
        selected = [token for token_start, token_end, token in ranges if token_start < end and token_end > start]
        if not selected or any(token.confidence < minimum_confidence for token in selected):
            return []
        xs = [point[0] for token in selected for point in token.polygon]
        ys = [point[1] for token in selected for point in token.polygon]
        regions.append((max(0.0, min(xs) - .005), max(0.0, min(ys) - .01), min(1.0, max(xs) + .005), min(1.0, max(ys) + .01)))
    return _merge(regions)


def _merge(regions: list[tuple[float, float, float, float]]) -> list[tuple[float, float, float, float]]:
    merged: list[tuple[float, float, float, float]] = []
    for region in regions:
        for index, existing in enumerate(merged):
            if not (region[2] < existing[0] or existing[2] < region[0] or region[3] < existing[1] or existing[3] < region[1]):
                merged[index] = (min(region[0], existing[0]), min(region[1], existing[1]), max(region[2], existing[2]), max(region[3], existing[3]))
                break
        else:
            merged.append(region)
    return merged


def _redact(image: Image.Image, regions: list[tuple[float, float, float, float]]) -> Image.Image:
    output = image.copy()
    draw = ImageDraw.Draw(output)
    for left, top, right, bottom in regions:
        draw.rectangle((int(left * output.width), int(top * output.height), int(right * output.width), int(bottom * output.height)), fill="black")
    return output


def _failed(status: AttachmentProcessingStatus, file_type: str) -> AttachmentProcessingResult:
    return AttachmentProcessingResult(status, "NONE", "NONE", "", (), (), AttachmentMetrics(file_type, 0, 0, 0, 0, 0, False, status))
