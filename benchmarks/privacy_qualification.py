"""Versioned synthetic held-out privacy qualification runner.

The corpus is fixed in source and is intentionally separate from primary
detector fixture names.  Attachment geometry uses independently authored text
and pixel boxes with a deterministic fixture OCR adapter; it qualifies the
privacy/geometry state machine, not general OCR recognition accuracy.
"""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
import json
from pathlib import Path
from typing import Iterable

from PIL import Image, ImageDraw, ImageFont

from pace_connector.attachments import LocalAttachmentProcessor, OcrToken
from pace_connector.contracts import AttachmentMetadata, LocalAttachment
from pace_connector.masking import LocalPrivacyMasker
from pace_connector.privacy import EgressPrivacyGate, LocalPrivacyDetector

CORPUS_VERSION = "m3-bq2-frozen-held-out-v1"


@dataclass(frozen=True)
class Case:
    category: str
    text: str
    entity: str


@dataclass(frozen=True)
class RegionCase:
    category: str
    entity: str
    pixels: tuple[int, int, int, int]
    image: Image.Image


def corpus() -> tuple[Case, ...]:
    # This corpus was generated and frozen only after the residual algorithm
    # was fixed.  It is deliberately disjoint from development probes and no
    # name below appears in privacy.py runtime rules.
    people = (
        "Rina Patel", "MARCUS EVANS", "ana silva", "Omar Aziz", "J. Chen",
        "K Chen", "Aisha-Rose Bello", "O'Connor Liam", "Min Jae Park", "Ravi Kumar",
        "Émile Laurent", "Sofía Núñez", "Håkon Berg", "İpek Kaya", "Renée Faure",
        "João Santos", "Chloë Brown", "Álvaro Ruiz", "Dr Marta de Sousa", "Prof David Ng",
    )
    emails = tuple(f"applicant{index:02d}.case{index}@synthetic.example.test" for index in range(1, 21))
    phones = tuple(f"+65 {prefix}{100 + index:03d} {4000 + index:04d}" for index, prefix in enumerate((3, 6, 8, 9) * 5, 1))
    nrics = tuple(f"S {1000000 + index:07d} A" if index % 2 else f"T-{1000000 + index:07d}-Z" for index in range(1, 21))
    references = tuple(
        f"Application: APP-{2026 + index % 2}-{100 + index:03d}" if index % 2
        else f"Reference REF-CASE-{100 + index:03d}"
        for index in range(1, 21)
    )
    cases: list[Case] = []
    # Lowercase PERSON is intentionally evaluated as a standalone field: that
    # is the published residual-sentinel scope, not a claim of lower-case NER.
    cases.extend(Case("PERSON", value if value.islower() else f"{value} asks about a programme intake.", value) for value in people)
    cases.extend(Case("EMAIL", f"Please use {value} for the reply.", value) for value in emails)
    cases.extend(Case("PHONE", f"Telephone contact: {value}.", value) for value in phones)
    cases.extend(Case("NRIC_FIN", f"Synthetic identity value {value}.", value) for value in nrics)
    cases.extend(Case("REFERENCE", f"Recorded sender value: {value}.", value) for value in references)
    return tuple(cases)


def negative_controls() -> tuple[str, ...]:
    # 100 independent business controls generated from public correspondence
    # concepts.  They are never copied into a runtime allowlist.
    subjects = ("Programme Details", "Programme Enquiry", "Payment Receipt", "Course Schedule", "Application Form", "Programme Information", "Payment Status", "General Enquiry", "Training Allowance", "Professional Certificate", "Data Analytics Programme", "Intake Status", "Fee Payment", "Student Services", "Programme Office", "Payment Confirmation", "Receipt Attached", "Dear Team", "Best Regards", "Application Status 2026")
    suffixes = ("", " for May", " guidance", " update", " 2026", " available")
    return tuple(f"{subject}{suffix}" for subject in subjects for suffix in suffixes[:5])


def _font(size: int):
    for candidate in ("/System/Library/Fonts/Supplemental/Arial.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/dejavu/DejaVuSans.ttf"):
        if Path(candidate).is_file(): return ImageFont.truetype(candidate, size)
    raise RuntimeError("qualification requires a system TrueType font")


def region_cases(cases: Iterable[Case]) -> tuple[RegionCase, ...]:
    result: list[RegionCase] = []
    font = _font(30)
    for index, case in enumerate(cases):
        image = Image.new("RGB", (1400, 180), "white")
        draw = ImageDraw.Draw(image)
        prefix = "Receipt / sender text: "
        x, y = 35, 65
        draw.text((x, y), prefix + case.entity, fill="black", font=font)
        start = x + int(draw.textlength(prefix, font=font))
        bbox = draw.textbbox((start, y), case.entity, font=font)
        # Independent synthetic GT: authored drawing bbox, never detector output.
        result.append(RegionCase(case.category, case.entity, bbox, image))
    return tuple(result)


class FixtureOcr:
    """Per-image deterministic fixture OCR: initial source then safe verification text."""
    def __init__(self, entity: str, pixels: tuple[int, int, int, int], image: Image.Image):
        left, top, right, bottom = pixels; width, height = image.size
        polygon = ((left / width, top / height), (right / width, top / height), (right / width, bottom / height), (left / width, bottom / height))
        self._entity = entity
        self._pixels = pixels
        self._polygon = polygon
        self._calls = 0

    def read(self, image):
        self._calls += 1
        if self._calls == 1:
            return [OcrToken(self._entity, 0, self._polygon, 1.0), OcrToken("receipt", 0, ((.02, .02), (.1, .02), (.1, .1), (.02, .1)), 1.0)]
        # The fixture OCR only yields safe verification words when independently
        # authored ground-truth pixels are actually blacked out. A detector miss
        # therefore re-emits the original entity and the sentinel rejects it.
        crop = image.crop(self._pixels).convert("L")
        black_ratio = sum(crop.histogram()[:16]) / (crop.width * crop.height)
        if black_ratio < .80:
            return [OcrToken(self._entity, 0, self._polygon, 1.0), OcrToken("receipt", 0, ((.02, .02), (.1, .02), (.1, .1), (.02, .1)), 1.0)]
        return [OcrToken("redacted", 0, ((.02, .02), (.1, .02), (.1, .1), (.02, .1)), 1.0), OcrToken("receipt", 0, ((.12, .02), (.2, .02), (.2, .1), (.12, .1)), 1.0)]


def _coverage(region: tuple[float, float, float, float], pixels: tuple[int, int, int, int], image: Image.Image) -> float:
    target = (pixels[0] / image.width, pixels[1] / image.height, pixels[2] / image.width, pixels[3] / image.height)
    left, top, right, bottom = max(region[0], target[0]), max(region[1], target[1]), min(region[2], target[2]), min(region[3], target[3])
    overlap = max(0.0, right - left) * max(0.0, bottom - top)
    area = (target[2] - target[0]) * (target[3] - target[1])
    return overlap / area if area else 0.0


def _canonical(body: str) -> dict[str, object]:
    return {
        "requestId": "rstn_req_000000000000000000000000000000aa",
        "correlationId": "rstn_cor_000000000000000000000000000000aa",
        "idempotencyKey": "rstn_idem_000000000000000000000000000000aa",
        "enquiry": {"currentMessage": {"subject": "programme", "body": body}, "permittedThread": [], "priorIssues": [], "attachmentEvidence": []},
    }


def _finalise_outbound(payload: dict[str, object], gate: EgressPrivacyGate, *, bypass_gate_for_mutation: bool = False) -> tuple[bool, str]:
    """Return (blocked, exact outbound JSON) after the final egress decision."""
    outbound = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if bypass_gate_for_mutation:
        return False, outbound
    try:
        gate.validate(payload)
        return False, outbound
    except Exception:
        return True, outbound


def evaluate(*, inject_unmasked_category: str | None = None, bypass_gate_for_mutation: bool = False) -> dict[str, object]:
    detector = LocalPrivacyDetector()
    gate = EgressPrivacyGate()
    session = LocalPrivacyMasker(detector).new_session()
    positives = corpus(); negatives = negative_controls()
    categories = sorted({case.category for case in positives})
    metrics = {category: {"cases": 0, "detector_hits": 0, "secondary_residual_hits": 0, "text_mask_hits": 0, "raw_egress_blocks": 0, "masked_egress_passes": 0, "masked_egress_blocks": 0, "attachment_cases": 0, "attachment_region_hits": 0, "coverage_at_least_80pct": 0, "verification_passes": 0, "canonical_leaks": 0, "primary_routes": {}} for category in categories}
    for case in positives:
        current = metrics[case.category]; current["cases"] += 1
        findings = detector.find(case.text)
        category_findings = [finding for finding in findings if finding.category == case.category]
        if category_findings:
            current["detector_hits"] += 1
            for finding in category_findings:
                current["primary_routes"][finding.detector] = current["primary_routes"].get(finding.detector, 0) + 1
        masked = session.mask(case.text).masked_text
        if case.entity not in masked: current["text_mask_hits"] += 1
        if gate._sentinel.scan_text(case.text): current["secondary_residual_hits"] += 1
        raw_blocked, _raw_json = _finalise_outbound(_canonical(case.text), gate)
        if raw_blocked: current["raw_egress_blocks"] += 1
        outbound_body = case.text if inject_unmasked_category == case.category else masked
        blocked, outbound_json = _finalise_outbound(_canonical(outbound_body), gate, bypass_gate_for_mutation=bypass_gate_for_mutation)
        if blocked:
            current["masked_egress_blocks"] += 1
        else:
            current["masked_egress_passes"] += 1
            # This is the actual final canonical JSON, not a pre-mask proxy.
            if case.entity in outbound_json:
                current["canonical_leaks"] += 1
    for fixture in region_cases(positives):
        current = metrics[fixture.category]; current["attachment_cases"] += 1
        stream = BytesIO(); fixture.image.save(stream, format="PNG")
        local = LocalAttachment(AttachmentMetadata("heldout.png", "image/png", len(stream.getvalue()), "attachment"), stream.getvalue())
        result = LocalAttachmentProcessor(ocr_engine=FixtureOcr(fixture.entity, fixture.pixels, fixture.image), detector=detector).process(local)
        if result.source_regions:
            current["attachment_region_hits"] += 1
            if max(_coverage(region, fixture.pixels, fixture.image) for _page, region in result.source_regions) >= .8:
                current["coverage_at_least_80pct"] += 1
        if result.status == "PRIVACY_VERIFIED": current["verification_passes"] += 1
    false_positives = sum(bool(detector.find(value)) for value in negatives)
    negative_egress_blocks = 0
    for value in negatives:
        blocked, _outbound = _finalise_outbound(_canonical(value), gate)
        negative_egress_blocks += int(blocked)
    return {"corpusVersion": CORPUS_VERSION, "positiveCases": len(positives), "negativeControls": len(negatives), "categories": metrics, "falsePositiveControls": false_positives, "negativeEgressBlocks": negative_egress_blocks, "notes": ["All corpus values are synthetic.", "Secondary PERSON residual hits apply only to this frozen synthetic corpus; they do not qualify general independent PERSON recognition.", "Business controls are frozen synthetic regression coverage assembled from runtime public-correspondence vocabulary; they are not an independent false-positive-rate estimate.", "Attachment regions are independent drawing ground truth and deterministic fixture-OCR geometry tests; they are not RapidOCR/Paddle recognition claims.", "Canonical leaks are counted only if independently grounded raw PII remains in final canonical JSON after the gate permits egress."]}


def report_markdown(results: dict[str, object]) -> str:
    lines = ["# Synthetic privacy qualification", "", f"Corpus version: `{results['corpusVersion']}`", "", f"Positive cases: {results['positiveCases']}; negative controls: {results['negativeControls']}", "", "| Category | Cases | Primary hits | Secondary residual hits (frozen cases) | Text masks | Combined raw egress blocks | Masked passes | Masked blocks | Attachment regions | >=80% coverage | Verification passes | Canonical leaks |", "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for category, values in results["categories"].items():
        lines.append("| {0} | {cases} | {detector_hits} | {secondary_residual_hits} | {text_mask_hits} | {raw_egress_blocks} | {masked_egress_passes} | {masked_egress_blocks} | {attachment_region_hits} | {coverage_at_least_80pct} | {verification_passes} | {canonical_leaks} |".format(category, **values))
    lines.extend(["", f"False-positive controls (primary): {results['falsePositiveControls']}", f"Negative controls blocked by egress sentinel: {results['negativeEgressBlocks']}", "", "## Scope and evidence limits", "", *[f"- {note}" for note in results["notes"]]])
    lines.extend(["", "## Primary detector routes", ""])
    for category, values in results["categories"].items(): lines.append(f"- {category}: {values['primary_routes']}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    results = evaluate()
    print(report_markdown(results), end="")
