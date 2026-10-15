"""CPU OCR comparison for the connector. Run one engine per process:
    taskset -c 0-3 python benchmarks/ocr_cpu_comparison.py "<engine>"  -> one JSON line
Needs, besides the connector: rapidocr==3.10.0 onnxtr[cpu-headless]==0.9.0 paddlepaddle==3.3.1 paddleocr==3.7.0.
Results: ocr-cpu-comparison-2026-10-15.md
"""
from __future__ import annotations

import json
import os
import re
import resource
import statistics
import sys
import time
from collections import Counter
from io import BytesIO
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageEnhance, ImageFilter, ImageFont

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ocr_backend_qualification as harness  # noqa: E402
from ocr_backend_qualification import qualify, safe_summary  # noqa: E402
from pace_connector.attachments import AttachmentProcessingLimits, LocalAttachmentProcessor, OcrToken, RapidOcrEngine  # noqa: E402

# The fixtures hold only PII, so after blackout nothing is left to OCR and the
# "fewer than 2 tokens" rule fails every fixture closed. Relax it for measurement only.
harness.LocalAttachmentProcessor = lambda **kw: LocalAttachmentProcessor(limits=AttachmentProcessingLimits(min_usable_tokens_per_page=0, max_elapsed_seconds=120), **kw)


class Paddle:
    def __init__(self) -> None:
        from paddleocr import PaddleOCR
        self._ocr = PaddleOCR(lang="en", use_doc_orientation_classify=False, use_doc_unwarping=False, use_textline_orientation=False, enable_mkldnn=False)

    def read(self, image):
        w, h = image.size
        out = []
        for page in self._ocr.predict(np.array(image.convert("RGB"))):
            for t, poly, s in zip(page["rec_texts"], page["rec_polys"], page["rec_scores"]):
                if str(t).strip():
                    out.append(OcrToken(str(t), 0, _norm(poly, w, h), float(s)))
        return out


def _norm(polygon, width, height):
    return tuple((max(0.0, min(1.0, float(x) / width)), max(0.0, min(1.0, float(y) / height))) for x, y in polygon)


class Rapid3:
    def __init__(self, version: str, det: str, rec: str, lang: str | None) -> None:
        from rapidocr import LangDet, LangRec, ModelType, OCRVersion, RapidOCR
        params = {"Det.ocr_version": OCRVersion(version), "Det.model_type": ModelType(det), "Rec.ocr_version": OCRVersion(version), "Rec.model_type": ModelType(rec), "Global.log_level": "error"}
        if version == "PP-OCRv5":
            params["Det.lang_type"] = LangDet.MULTI
        if version == "PP-OCRv6":
            params["Det.lang_type"] = LangDet.EN
        if lang:
            params["Rec.lang_type"] = LangRec(lang)
        self._ocr = RapidOCR(params=params)

    def read(self, image):
        out = self._ocr(np.array(image.convert("RGB")))
        if out.boxes is None:
            return []
        w, h = image.size
        return [OcrToken(str(t), 0, _norm(b, w, h), float(s)) for b, t, s in zip(out.boxes, out.txts, out.scores)]


class OnnxTR:
    def __init__(self, det: str, reco: str) -> None:
        from onnxtr.models import ocr_predictor
        self._ocr = ocr_predictor(det_arch=det, reco_arch=reco, assume_straight_pages=False, detect_orientation=False)

    def read(self, image):
        doc = self._ocr([np.array(image.convert("RGB"))])
        tokens = []
        for block in doc.pages[0].blocks:
            for line in block.lines:
                for word in line.words:
                    g = np.array(word.geometry)
                    if g.shape == (2, 2):
                        (x0, y0), (x1, y1) = g
                        g = np.array([[x0, y0], [x1, y0], [x1, y1], [x0, y1]])
                    tokens.append(OcrToken(word.value, 0, tuple((float(x), float(y)) for x, y in g), float(word.confidence)))
        return tokens


ENGINES = {
    "rapid1-v4mobile (current)": RapidOcrEngine,
    "rapid3-v5mobile-en": lambda: Rapid3("PP-OCRv5", "mobile", "mobile", "en"),
    "rapid3-v6small": lambda: Rapid3("PP-OCRv6", "small", "small", "en"),
    "rapid3-v6medium": lambda: Rapid3("PP-OCRv6", "medium", "medium", "en"),
    "onnxtr-fast+crnn_mobile": lambda: OnnxTR("fast_base", "crnn_mobilenet_v3_large"),
    "onnxtr-db50+parseq": lambda: OnnxTR("db_resnet50", "parseq"),
    "paddle-native (PP-OCR default)": Paddle,
}

# ---------------------------------------------------------------- realistic text set

FONTS = ["/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSerif.ttf",
         "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf", "/usr/share/fonts/truetype/liberation/LiberationSerif-Regular.ttf"]
FONTS = [f for f in FONTS if Path(f).is_file()]


def font(i: int, size: int):
    return ImageFont.truetype(FONTS[i % len(FONTS)], size)


def page(lines, size=(1240, 1754), fsize=30, fi=0, x=80, y=90, gap=1.55, bg="white", fg="black"):
    img = Image.new("RGB", size, bg)
    d = ImageDraw.Draw(img)
    f = font(fi, fsize)
    for line in lines:
        d.text((x, y), line, fill=fg, font=f)
        y += int(fsize * gap)
    return img


RECEIPT = ["NANYANG TECHNOLOGICAL UNIVERSITY", "Official Receipt No. OR-2026-0048213", "Date: 26 Aug 2026",
           "Received from: Tan Mei Ling", "Programme: Graduate Certificate in Applied Data Analytics",
           "Course fee (before GST)   S$3,363.00", "GST 9%   S$302.67", "Total paid   S$3,665.67",
           "Payment method: PayNow   Ref 8817-2231-0045", "SkillsFuture Credit applied: S$500.00",
           "Balance due: S$0.00", "Thank you for your payment."]
LETTER = ["Dear Admissions Team,", "I am writing to ask whether my earlier module, Introduction to",
          "Machine Learning (EE7207), completed in January 2025, can be credited", "towards the Master of Science in Artificial Intelligence. I attach my",
          "transcript and the course outline for your reference. My application", "number is APP-2026-117342 and my mobile is +65 9123 4567.",
          "Could you also confirm the deadline for the August 2026 intake and", "whether the programme accepts part-time candidates?",
          "Yours sincerely,", "Lim Wei Jie"]
SCREEN = ["PayNow transfer successful", "To: NTU PaCE", "Amount: SGD 1,250.00", "Reference: INV-778201",
          "Transaction ID 20260826-ABX9-4410", "26 Aug 2026, 14:32", "From account: POSB eSavings ***-*4-1182",
          "Share receipt    Done"]
TRANSCRIPT = ["Course Code   Course Title                         AU   Grade",
              "AI6101   Introduction to AI and Ethics   3   A-", "AI6102   Machine Learning Methods   3   B+",
              "AI6103   Deep Learning and Applications   3   A", "AI6121   Computer Vision   3   B",
              "Cumulative GPA: 4.12 / 5.00", "Date of issue: 03 Jul 2026"]


def text_set():
    items = []
    items.append(("receipt clean", page(RECEIPT, fi=0), RECEIPT))
    items.append(("receipt serif small", page(RECEIPT, fsize=20, fi=1), RECEIPT))
    letter = page(LETTER, fi=3, fsize=28)
    items.append(("letter clean", letter, LETTER))
    # scanned: slight rotation, noise, JPEG q40, greyscale
    scan = letter.rotate(1.2, expand=False, fillcolor="white").convert("L")
    arr = np.clip(np.array(scan).astype(np.int16) + np.random.default_rng(3).normal(0, 14, scan.size[::-1]), 0, 255).astype(np.uint8)
    buf = BytesIO(); Image.fromarray(arr).save(buf, format="JPEG", quality=40)
    items.append(("letter scanned (1.2deg, noise, jpeg)", Image.open(BytesIO(buf.getvalue())).convert("RGB"), LETTER))
    # phone photo: 3 deg, blur, uneven lighting, downscale
    photo = letter.rotate(3, expand=True, fillcolor=(235, 235, 230)).filter(ImageFilter.GaussianBlur(1.2))
    grad = np.linspace(0.75, 1.0, photo.size[0])[None, :, None]
    photo = Image.fromarray(np.clip(np.array(photo) * grad, 0, 255).astype(np.uint8)).resize((photo.size[0] * 2 // 3, photo.size[1] * 2 // 3))
    items.append(("letter phone photo (3deg, blur, shading)", photo, LETTER))
    shot = page(SCREEN, size=(750, 1334), fsize=26, fi=2, x=50, y=120, gap=2.2, bg=(245, 246, 248), fg=(40, 40, 50))
    items.append(("payment screenshot", shot, SCREEN))
    items.append(("payment screenshot low-res", shot.resize((375, 667)), SCREEN))
    items.append(("transcript table", page(TRANSCRIPT, size=(1400, 700), fsize=24, fi=0), TRANSCRIPT))
    return items


def words(text: str) -> Counter:
    return Counter(w.strip(".,:;").lower() for w in text.split() if w.strip(".,:;"))


def text_accuracy(engine):
    rows, durations = [], []
    hit = ref_total = out_total = 0
    for name, img, ref in text_set():
        t = time.monotonic(); tokens = engine.read(img); durations.append((time.monotonic() - t) * 1000)
        r, o = words(" ".join(ref)), words(" ".join(tok.text for tok in tokens))
        h = sum((r & o).values())
        hit += h; ref_total += sum(r.values()); out_total += sum(o.values())
        rows.append((name, round(100 * h / sum(r.values()), 1)))
    return {"word_recall_pct": round(100 * hit / ref_total, 1), "word_precision_pct": round(100 * hit / max(1, out_total), 1),
            "per_doc_recall": rows, "page_p50_ms": int(statistics.median(durations)), "page_max_ms": int(max(durations))}


def main():
    name = sys.argv[1]
    factory = ENGINES[name]
    started = time.monotonic(); engine = factory(); cold = int((time.monotonic() - started) * 1000)
    engine.read(page(["warm up"], size=(400, 120)))
    acc = text_accuracy(engine)
    priv = safe_summary(qualify(name, lambda: engine))
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024
    print(json.dumps({"engine": name, "cold_start_ms": cold, "peak_rss_mb": rss, "text": acc, "privacy_suite": priv}))


if __name__ == "__main__":
    main()
