"""Local detector for personal details other than names.

Addresses (in any country), dates of birth, identity and account numbers (passport, bank, card),
links to a person's own pages, passwords, and phone numbers and email addresses that the
structural rules do not cover (other countries, written out in words). Names stay with the
name model and the rules in `names`.

The detector is a token classifier run on the CPU with onnxruntime and tokenizers (4-bit weights,
about 0.9 GB, about 0.15 s per email on 4 cores). Its files are not in the package: they live in
a folder given by `PACE_DETAIL_MODEL_DIR` (default `~/.cache/pace-connector/detail-model`) and
are checked against pinned SHA-256 digests. A missing or changed file fails closed, as a missing
name model does.

Three filters keep public details the engine needs readable:
- a date is a date of birth only when "birth", "DOB" or "born" comes just before it, so intake
  dates and deadlines stay;
- an address with PaCE's or NTU's own postal code is public;
- a course code ("EE7207"), or a piece of one, is not a personal detail.
"""

from __future__ import annotations

from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import re

from .errors import PrivacyDetectorFailureError

MODEL_FILES = {
    "config.json": "b2b26a4a4a000639ad30b0c264adbefe365bdb567fbd7bb27303b8c438375bd1",
    "model_q4.onnx": "8f7dee8b46d096f052b359375dfba5d983cc4d18c44a783bf548615c472f8dea",
    "model_q4.onnx_data": "f30998e28c71c5374cc7e8b7de8f0f83e981592c0c2d652d2ad4928454dbb496",
    "tokenizer.json": "0614fe83cadab421296e664e1f48f4261fa8fef6e03e63bb75c20f38e37d07d3",
}
DEFAULT_MODEL_DIR = Path.home() / ".cache" / "pace-connector" / "detail-model"

# The model's categories and the connector's. Its person category is not used: names have their own model.
_CATEGORIES = {
    "private_address": "ADDRESS", "private_date": "DATE_OF_BIRTH", "account_number": "ID_NUMBER",
    "private_url": "URL", "secret": "SECRET", "private_email": "EMAIL", "private_phone": "PHONE",
}
# PaCE's and NTU's own postal codes: an address with one of them is public. Connector-owned configuration.
PUBLIC_POSTAL_CODES = ("639798", "138664", "639673")
_BIRTH_CUE = re.compile(r"(?:birth|\bd\.?o\.?b\b|\bborn\b)\W*(?:\w+\W+){0,3}$", re.IGNORECASE)
_COURSE_CODE = re.compile(r"\b[A-Z]{2,3}\d{4}\b")
_WINDOW, _OVERLAP = 2048, 128  # tokens per model call, and the overlap between calls for long attachments


def model_dir() -> Path:
    configured = os.environ.get("PACE_DETAIL_MODEL_DIR")
    return Path(configured).expanduser() if configured else DEFAULT_MODEL_DIR


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


class DetailDetector:
    """`spans(text)` gives (start, end, category) for each personal detail, filtered as above."""

    def __init__(self, path: Path | None = None, threads: int | None = None) -> None:
        path = path or model_dir()
        try:
            for name, expected in MODEL_FILES.items():
                if _sha256(path / name) != expected:
                    raise PrivacyDetectorFailureError()
            import numpy
            import onnxruntime
            from tokenizers import Tokenizer
            options = onnxruntime.SessionOptions()
            options.intra_op_num_threads = threads or int(os.environ.get("PACE_DETAIL_MODEL_THREADS", "4"))
            self._numpy = numpy
            self._tokenizer = Tokenizer.from_file(str(path / "tokenizer.json"))
            self._session = onnxruntime.InferenceSession(str(path / "model_q4.onnx"), options, providers=["CPUExecutionProvider"])
            self._labels = {int(key): value for key, value in json.loads((path / "config.json").read_text())["id2label"].items()}
        except PrivacyDetectorFailureError:
            raise
        except Exception as error:
            raise PrivacyDetectorFailureError() from error

    def _token_labels(self, text: str) -> list[tuple[str, float, int, int]]:
        numpy = self._numpy
        encoding = self._tokenizer.encode(text)
        ids, offsets = encoding.ids, encoding.offsets
        best: dict[int, tuple[float, int]] = {}
        start = 0
        while True:
            window = numpy.array([ids[start:start + _WINDOW]], dtype=numpy.int64)
            logits = self._session.run(None, {"input_ids": window, "attention_mask": numpy.ones_like(window)})[0][0]
            probabilities = numpy.exp(logits - logits.max(-1, keepdims=True))
            probabilities /= probabilities.sum(-1, keepdims=True)
            for index, row in enumerate(probabilities):
                label = int(row.argmax())
                if start + index not in best or row[label] > best[start + index][0]:
                    best[start + index] = (float(row[label]), label)
            if start + _WINDOW >= len(ids):
                break
            start += _WINDOW - _OVERLAP
        return [(self._labels[best[i][1]], best[i][0], s, e) for i, (s, e) in enumerate(offsets) if e > s and i in best]

    def spans(self, text: str) -> list[tuple[int, int, str]]:
        if not text.strip():
            return []
        runs: list[list] = []
        for label, score, start, end in self._token_labels(text):
            if label == "O" or score < 0.5:
                continue
            prefix, category = label.split("-", 1)
            while start < end and text[start].isspace():
                start += 1
            gap = text[runs[-1][1]:start] if runs else ""
            if runs and runs[-1][2] == category and prefix in ("I", "E") and "\n\n" not in gap and len(gap) <= 3:
                runs[-1][1] = end
            else:
                runs.append([start, end, category])
        codes = [match.span() for match in _COURSE_CODE.finditer(text)]
        out = []
        for start, end, category in runs:
            connector_category = _CATEGORIES.get(category)
            value = text[start:end]
            if connector_category is None or not value.strip():
                continue
            if connector_category == "DATE_OF_BIRTH" and not _BIRTH_CUE.search(text[max(0, start - 40):start]):
                continue
            if any(cs <= start and end <= ce for cs, ce in codes):
                continue
            if connector_category == "ADDRESS" and any(code in value for code in PUBLIC_POSTAL_CODES):
                continue
            out.append((start, end, connector_category))
        return out


@lru_cache(maxsize=2)
def load(path: str | None = None) -> DetailDetector:
    """One detector per process and folder: loading checks about 0.9 GB of digests."""
    return DetailDetector(Path(path) if path else None)
