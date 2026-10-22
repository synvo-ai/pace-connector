from __future__ import annotations

import unittest

from benchmarks.privacy_development_corpus import DEVELOPMENT_BUSINESS_PROBES, DEVELOPMENT_PERSON_PROBES
from benchmarks.privacy_qualification import corpus, evaluate, negative_controls, report_markdown
from pace_connector.privacy import _PUBLIC_CORRESPONDENCE_WORDS, public_institutional_entity_registry


class M3BQQualificationRunnerTests(unittest.TestCase):
    def test_versioned_held_out_corpus_meets_minimum_counts_and_machine_metrics(self) -> None:
        values = corpus(); counts = {category: sum(item.category == category for item in values) for category in {item.category for item in values}}
        self.assertEqual(set(counts), {"PERSON", "EMAIL", "PHONE", "NRIC_FIN", "REFERENCE"})
        self.assertTrue(all(count >= 20 for count in counts.values()))
        self.assertGreaterEqual(len(negative_controls()), 100)
        results = evaluate()
        self.assertEqual(results["positiveCases"], 100)
        self.assertEqual(results["negativeControls"], 100)
        expected = {
            "EMAIL": {"cases": 20, "detector_hits": 20, "text_mask_hits": 20, "raw_egress_blocks": 20, "masked_egress_passes": 20, "masked_egress_blocks": 0, "attachment_region_hits": 20, "coverage_at_least_80pct": 20, "verification_passes": 20, "canonical_leaks": 0},
            "NRIC_FIN": {"cases": 20, "detector_hits": 20, "text_mask_hits": 20, "raw_egress_blocks": 20, "masked_egress_passes": 20, "masked_egress_blocks": 0, "attachment_region_hits": 20, "coverage_at_least_80pct": 20, "verification_passes": 20, "canonical_leaks": 0},
            # Since the name-rule change (15 Oct) the name rules mask all 20 held-out names; before it,
            # four ("Min Jae Park", "Émile Laurent", ...) were missed and stopped by the egress check.
            "PERSON": {"cases": 20, "detector_hits": 20, "text_mask_hits": 20, "raw_egress_blocks": 20, "masked_egress_passes": 20, "masked_egress_blocks": 0, "attachment_region_hits": 20, "coverage_at_least_80pct": 20, "verification_passes": 20, "canonical_leaks": 0},
            "PHONE": {"cases": 20, "detector_hits": 20, "text_mask_hits": 20, "raw_egress_blocks": 20, "masked_egress_passes": 20, "masked_egress_blocks": 0, "attachment_region_hits": 20, "coverage_at_least_80pct": 20, "verification_passes": 20, "canonical_leaks": 0},
            "REFERENCE": {"cases": 20, "detector_hits": 20, "text_mask_hits": 20, "raw_egress_blocks": 20, "masked_egress_passes": 20, "masked_egress_blocks": 0, "attachment_region_hits": 20, "coverage_at_least_80pct": 20, "verification_passes": 20, "canonical_leaks": 0},
        }
        for category, values in expected.items():
            with self.subTest(category=category):
                actual = results["categories"][category]
                self.assertEqual({key: actual[key] for key in values}, values)
        self.assertGreater(results["categories"]["PERSON"]["primary_routes"].get("spacy-en_core_web_trf", 0), 0)
        self.assertLess(results["categories"]["PERSON"]["primary_routes"].get("primary-title-person", 0), 20)
        self.assertEqual((results["falsePositiveControls"], results["negativeEgressBlocks"]), (0, 0))
        self.assertIn("Synthetic privacy qualification", report_markdown(results))

    def test_runtime_has_no_qualification_fixture_name_or_phrase_allowlist(self) -> None:
        # Only declared real institutional entities may overlap the benchmark.
        fixture_literals = {item.entity.casefold() for item in corpus()} | {item.casefold() for item in negative_controls()}
        development_literals = {item.casefold() for item in DEVELOPMENT_PERSON_PROBES + DEVELOPMENT_BUSINESS_PROBES}
        approved_entities = set(public_institutional_entity_registry().entities)
        self.assertEqual(fixture_literals & approved_entities, set())
        self.assertEqual(development_literals & approved_entities, set())
        # The business policy is token-level general language, never copied
        # full fixture phrases.  PERSON names cannot be safety rules at all.
        self.assertFalse(any(" " in item for item in _PUBLIC_CORRESPONDENCE_WORDS))
        self.assertFalse(any(item.casefold() in _PUBLIC_CORRESPONDENCE_WORDS for item in DEVELOPMENT_PERSON_PROBES))

    def test_mutation_injected_raw_pii_is_counted_as_a_canonical_leak(self) -> None:
        # Deliberately bypassing the final gate is test-only; it proves the
        # metric is not a permanently-zero counter.
        mutated = evaluate(inject_unmasked_category="EMAIL", bypass_gate_for_mutation=True)
        self.assertEqual(mutated["categories"]["EMAIL"]["canonical_leaks"], 20)


if __name__ == "__main__": unittest.main()
