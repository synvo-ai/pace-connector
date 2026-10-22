"""Measure the two privacy rates on `egress_corpus`: ordinary emails blocked, and names missed.

    PYTHONPATH=. .venv/bin/python benchmarks/egress_rates.py [--verbose] [--spacy-model en_core_web_trf]

A name counts as missed when it, or any of its words that is not also an English word, is in
the masked request (titles and bin/binte/s/o excluded). A missed name in a blocked email went to Manual handling; in a sent email it
leaked. Over-masked lists text masked as a person that is not a person's name.
"""

from __future__ import annotations

import argparse
import json
import re
import sys

from pace_connector.contracts import ConnectorInput
from pace_connector.errors import ConnectorError
from pace_connector.masking import LocalPrivacyMasker
from pace_connector.names import is_known_word
from pace_connector.privacy import EgressPrivacyGate, LocalPrivacyDetector
from pace_connector.server import message_ids
from pace_connector.service import MimePrivacyConnector

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from egress_corpus import dev_cases, hard_cases, held_out_cases  # noqa: E402

_NOT_NAME_WORDS = {"dr", "mr", "ms", "mrs", "prof", "professor", "bin", "binte", "s/o", "d/o"}


class _Unused:
    def analyse(self, canonical_request: dict) -> dict:
        raise AssertionError("not called")


def _outbound_text(canonical: dict) -> str:
    enquiry = canonical["enquiry"]
    parts = [enquiry["currentMessage"]["subject"], enquiry["currentMessage"]["body"]]
    parts += [item["excerpt"] for item in enquiry["attachmentEvidence"]]
    return "\n".join(parts)


def run(cases, detector, verbose: bool) -> dict:
    connector = MimePrivacyConnector(_Unused(), LocalPrivacyMasker(detector, nonce_secret=b"b" * 32), privacy_detector=detector)
    gate = EgressPrivacyGate()
    blocked, names, missed_blocked, leaked, over = [], 0, [], [], []
    for case_id, source, gold in cases:
        connector_input = ConnectorInput(source.get("raw_eml", b""), **message_ids("bench:" + case_id), graph_message=source.get("graph_message"))
        try:
            canonical, session, known_names = connector._build_canonical_request(connector_input)
        except ConnectorError as error:
            blocked.append((case_id, error.code))
            continue
        try:
            gate.validate(canonical, known_names=known_names)
            is_blocked = False
        except ConnectorError:
            is_blocked = True
            blocked.append((case_id, "EGRESS"))
        text = _outbound_text(canonical)
        gold = [(item, 0) if isinstance(item, str) else item for item in gold]
        gold_words = {word.lower() for name, _n in gold for word in name.split() if word.lower() not in _NOT_NAME_WORDS}
        for name, ordinary in gold:
            names += 1
            # The whole name, or any of its words that is not also an English word ("Will", "Tan").
            words = [word for word in name.split() if word.lower() not in _NOT_NAME_WORDS and not is_known_word(word)]
            full = len(re.findall(rf"(?<![\w'’-]){re.escape(name)}(?![\w'’-])", text))
            if full > ordinary or any(re.search(rf"(?<![\w'’-]){re.escape(word)}(?![\w'’-])", text, re.IGNORECASE) for word in words):
                (missed_blocked if is_blocked else leaked).append((case_id, name))
        for placeholder, raw in session._placeholder_to_raw.items():
            if "_PERSON_" in placeholder and not ({word.lower() for word in re.findall(r"[\w'’-]+", raw)} & gold_words):
                over.append((case_id, raw))
        if verbose and is_blocked:
            print(f"--- {case_id} blocked\n{text}\n")
    return {"emails": len(cases), "blocked": blocked, "names": names, "missed_blocked": missed_blocked, "leaked": leaked, "over_masked": over}


def _report(label: str, result: dict) -> None:
    egress = [case for case, code in result["blocked"] if code == "EGRESS"]
    other = [f"{case} ({code})" for case, code in result["blocked"] if code != "EGRESS"]
    missed = len(result["missed_blocked"]) + len(result["leaked"])
    print(f"## {label}")
    print(f"emails blocked by the egress check: {len(egress)}/{result['emails']}  {egress}")
    if other:
        print(f"emails stopped before the check: {other}")
    print(f"names missed by masking: {missed}/{result['names']}  (blocked: {result['missed_blocked']}; leaked: {result['leaked']})")
    print(f"over-masked as a person: {len(result['over_masked'])}  {result['over_masked']}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--spacy-model", default="en_core_web_sm", help="e.g. en_core_web_trf (install it first)")
    args = parser.parse_args()
    detector = LocalPrivacyDetector(args.spacy_model)
    _report("dev (mock emails, two integration-shaped samples, examples)", run(dev_cases(), detector, args.verbose))
    _report("held-out (written before the fix; three fixes after its first run)", run(held_out_cases(), detector, args.verbose))
    _report("hard (written after the fix, run once)", run(hard_cases(), detector, args.verbose))


if __name__ == "__main__":
    main()
