"""Synthetic-only, local OCR privacy qualification; emits aggregate-safe metrics."""

from __future__ import annotations

import sys

from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
import statistics
import time

import numpy as np
from PIL import Image, ImageDraw, ImageEnhance, ImageFilter, ImageFont

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
from pdf_fixtures import image_pdf  # noqa: E402
from pace_connector.attachments import LocalAttachmentProcessor, OcrEngine, PaddleOcrEngine, RapidOcrEngine, SyntheticFixtureDetector, _align
from pace_connector.contracts import AttachmentMetadata, LocalAttachment


_VALUES = ("Alice Example", "alice.synthetic@example.test", "+65 8123 4567", "SYN-RECEIPT-001")


@dataclass(frozen=True)
class Fixture:
    category: str
    image: Image.Image
    expected_entities: int
    ground_truth_regions: tuple[tuple[float, float, float, float], ...]
    as_pdf: bool = False
    pages: int = 1


@dataclass(frozen=True)
class Result:
    backend: str
    fixture_count: int
    expected_entities: int
    text_matches: int
    region_matches: int
    ground_truth_entities: int
    coverage_matches: int
    verification_failures: int
    false_positive_regions: int
    ocr_durations_ms: tuple[int, ...]
    redaction_durations_ms: tuple[int, ...]
    cold_start_ms: int
    failed_categories: tuple[str, ...]


def _font(size: int) -> ImageFont.FreeTypeFont:
    for candidate in (
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    ):
        if Path(candidate).is_file():
            return ImageFont.truetype(candidate, size)
    raise RuntimeError("A system TrueType font is required for synthetic OCR qualification.")


def _base(size: tuple[int, int] = (1200, 700), font_size: int = 38, *, table: bool = False, columns: bool = False, boundary: bool = False, split_phone: bool = False, split_email: bool = False) -> Fixture:
    image = Image.new("RGB", size, "white")
    draw = ImageDraw.Draw(image)
    font = _font(font_size)
    positions = [(40, 90 + index * max(font_size + 18, 55)) for index in range(len(_VALUES))]
    if columns:
        positions = [(35, 100), (610, 100), (35, 260), (610, 260)]
    if boundary:
        positions = [(8, 8), (size[0] - 420, 8), (8, size[1] - 70), (size[0] - 330, size[1] - 70)]
    if table:
        for x in (20, size[0] // 2, size[0] - 20): draw.line((x, 40, x, size[1] - 40), fill="gray", width=2)
        for y in (40, 180, 320, 460, size[1] - 40): draw.line((20, y, size[0] - 20, y), fill="gray", width=2)
    regions: list[tuple[float, float, float, float]] = []
    values = list(_VALUES)
    if split_phone: values[2] = "+65  8123  4567"
    if split_email: values[1] = "alice.synthetic @ example . test"
    for value, (x, y) in zip(values, positions):
        draw.text((x, y), value, fill="black", font=font)
        box = draw.textbbox((x, y), value, font=font)
        regions.append((box[0] / size[0], box[1] / size[1], box[2] / size[0], box[3] / size[1]))
    return Fixture("clean receipt", image, len(_VALUES), tuple(regions))


def fixtures() -> list[Fixture]:
    base = _base()
    result = [base, Fixture("12px small text", _base(font_size=14).image, 4, ()), Fixture("low-resolution screenshot", base.image.resize((600, 350)), 4, ())]
    encoded = BytesIO(); base.image.save(encoded, format="JPEG", quality=35); result.append(Fixture("JPEG compression", Image.open(BytesIO(encoded.getvalue())).convert("RGB"), 4, ()))
    result += [
        Fixture("mild blur", base.image.filter(ImageFilter.GaussianBlur(1.0)), 4, ()),
        Fixture("grayscale low contrast", ImageEnhance.Contrast(base.image.convert("L")).enhance(.45).convert("RGB"), 4, ()),
        Fixture("2-degree rotation", base.image.rotate(2, expand=True, fillcolor="white"), 4, ()),
        Fixture("5-degree rotation", base.image.rotate(5, expand=True, fillcolor="white"), 4, ()),
        Fixture("10-degree rotation", base.image.rotate(10, expand=True, fillcolor="white"), 4, ()),
    ]
    noisy = np.array(base.image).astype(np.int16) + np.random.default_rng(7).normal(0, 18, np.array(base.image).shape)
    result += [
        Fixture("scan-like noise", Image.fromarray(np.clip(noisy, 0, 255).astype(np.uint8)), 4, ()),
        Fixture("table layout", _base(table=True).image, 4, _base(table=True).ground_truth_regions),
        Fixture("multi-column layout", _base(columns=True).image, 4, _base(columns=True).ground_truth_regions),
        Fixture("text near boundary", _base(boundary=True).image, 4, _base(boundary=True).ground_truth_regions),
        Fixture("multi-token name", base.image, 4, base.ground_truth_regions),
        Fixture("split Singapore phone", _base(split_phone=True).image, 4, _base(split_phone=True).ground_truth_regions),
        Fixture("email split across tokens", _base(split_email=True).image, 4, _base(split_email=True).ground_truth_regions),
        Fixture("synthetic identifier", base.image, 4, base.ground_truth_regions),
        Fixture("scanned PDF", base.image, 4, base.ground_truth_regions, as_pdf=True),
        Fixture("multi-page scanned PDF", base.image, 8, base.ground_truth_regions * 2, as_pdf=True, pages=2),
    ]
    public = Image.new("RGB", (900, 220), "white"); ImageDraw.Draw(public).text((30, 70), "Public programme information", fill="black", font=_font(34))
    result.append(Fixture("no synthetic PII", public, 0, ()))
    return result


def _attachment(fixture: Fixture) -> LocalAttachment:
    output = BytesIO()
    if not fixture.as_pdf:
        fixture.image.save(output, format="PNG")
        return LocalAttachment(AttachmentMetadata("synthetic.png", "image/png", len(output.getvalue()), "attachment"), output.getvalue())
    page_image = BytesIO(); fixture.image.save(page_image, format="PNG")
    content = image_pdf(fixture.image.width / 2, fixture.image.height / 2, page_image.getvalue(), fixture.pages)
    return LocalAttachment(AttachmentMetadata("synthetic.pdf", "application/pdf", len(content), "attachment"), content)


def _covers(redaction: tuple[float, float, float, float], target: tuple[float, float, float, float]) -> bool:
    left, top = max(redaction[0], target[0]), max(redaction[1], target[1])
    right, bottom = min(redaction[2], target[2]), min(redaction[3], target[3])
    intersection = max(0.0, right - left) * max(0.0, bottom - top)
    target_area = (target[2] - target[0]) * (target[3] - target[1])
    return target_area > 0 and intersection / target_area >= .8


def qualify(name: str, factory) -> Result:
    started = time.monotonic(); engine: OcrEngine = factory(); cold_start_ms = int((time.monotonic() - started) * 1000)
    detector = SyntheticFixtureDetector()
    processor = LocalAttachmentProcessor(ocr_engine=engine, detector=detector)
    text_matches = region_matches = coverage_matches = expected = known_regions = verification_failures = false_positive_regions = 0
    ocr_durations: list[int] = []; redaction_durations: list[int] = []; failures: set[str] = set()
    for fixture in fixtures():
        attachment = _attachment(fixture)
        result = processor.process(attachment)
        expected += fixture.expected_entities
        if result.status == "REDACTION_VERIFICATION_FAILED":
            verification_failures += 1; failures.add(fixture.category)
        if result.status not in {"PRIVACY_VERIFIED", "REDACTION_VERIFICATION_FAILED"}: failures.add(fixture.category)
        ocr_durations.append(result.metrics.ocr_duration_ms); redaction_durations.append(result.metrics.redaction_duration_ms)
        # Qualification-only recognition probe uses the same engine and the
        # same detector/alignment as the processing run. It is needed because
        # a fail-closed processor deliberately discards raw text on failure.
        fixture_text_matches = fixture_region_matches = 0
        for _page in range(fixture.pages):
            tokens = engine.read(fixture.image)
            matches = detector.spans(" ".join(token.text for token in tokens))
            detected = min(len(matches), fixture.expected_entities // fixture.pages)
            fixture_text_matches += detected
            fixture_region_matches += min(len(_align(matches, tokens, .5)), detected)
        text_matches += fixture_text_matches
        region_matches += fixture_region_matches
        if fixture_text_matches < fixture.expected_entities or fixture_region_matches < fixture.expected_entities:
            failures.add(fixture.category)
        if fixture.expected_entities == 0: false_positive_regions += len(result.source_regions)
        if fixture.ground_truth_regions:
            known_regions += len(fixture.ground_truth_regions)
            output_regions = [region for _page, region in result.source_regions]
            coverage_matches += sum(any(_covers(region, target) for region in output_regions) for target in fixture.ground_truth_regions)
    return Result(name, len(fixtures()), expected, text_matches, region_matches, known_regions, coverage_matches, verification_failures, false_positive_regions, tuple(ocr_durations), tuple(redaction_durations), cold_start_ms, tuple(sorted(failures)))


def percentile(values: tuple[int, ...], p: float) -> int:
    if not values: return 0
    ordered = sorted(values); return ordered[min(len(ordered) - 1, round((len(ordered) - 1) * p))]


def safe_summary(result: Result) -> dict[str, object]:
    return {
        "backend": result.backend,
        "fixture_count": result.fixture_count,
        "pii_text_recall": f"{result.text_matches}/{result.expected_entities}",
        "pii_region_recall": f"{result.region_matches}/{result.expected_entities}",
        "region_coverage": f"{result.coverage_matches}/{result.ground_truth_entities}",
        "verification_failures": result.verification_failures,
        "false_positive_regions": result.false_positive_regions,
        "ocr_p50_ms": percentile(result.ocr_durations_ms, .5),
        "ocr_p95_ms": percentile(result.ocr_durations_ms, .95),
        "redaction_verification_total_ms": sum(result.redaction_durations_ms),
        "cold_start_ms": result.cold_start_ms,
        "failed_categories": list(result.failed_categories),
    }


if __name__ == "__main__":
    import json
    print(json.dumps([safe_summary(qualify("RapidOCR", RapidOcrEngine)), safe_summary(qualify("PaddleOCR", PaddleOcrEngine))], indent=2))
