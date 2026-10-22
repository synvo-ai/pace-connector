"""Personal details other than names: the detail model, the labelled-value rules, and the egress check."""

import tempfile
import unittest
from pathlib import Path

from pace_connector.details import DetailDetector
from pace_connector.errors import PrivacyDetectorFailureError
from pace_connector.masking import LocalPrivacyMasker
from pace_connector.privacy import EgressPrivacySentinel, LocalPrivacyDetector, PiiFinding, _deduplicate


class DetailMaskingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.detector = LocalPrivacyDetector()

    def masked(self, text):
        return LocalPrivacyMasker(self.detector).new_session().mask(text).masked_text

    def test_addresses_dates_of_birth_and_numbers_are_masked(self):
        text = (
            "Please mail the certificate to Blk 98 Punggol Field #15-631, Singapore 764579.\n"
            "Date of birth: 14/07/1993\nPassport: K1234567A\nYou can call me on +60 12-345 6789.\n"
            "Refund to my DBS account 012-345678-9 please. My LinkedIn is linkedin.com/in/tan-wei-ming-88b2."
        )
        masked = self.masked(text)
        for value in ("98", "#15-631", "764579", "14/07/1993", "K1234567A", "345 6789", "345678", "tan-wei-ming"):
            with self.subTest(value=value):
                self.assertNotIn(value, masked)
        for category in ("ADDRESS", "DATE_OF_BIRTH", "ID_NUMBER", "URL"):
            self.assertIn(f"[[PII_{category}_", masked)

    def test_labelled_values_are_masked(self):
        masked = self.masked("My matric no. is U2012345K and my student number was 2022280453. The password I set is Kopi-O6752.")
        for value in ("U2012345K", "2022280453", "Kopi-O6752"):
            with self.subTest(value=value):
                self.assertNotIn(value, masked)

    def test_public_details_stay(self):
        text = (
            "Is the July 2027 intake still open? Applications close on 15 November 2026. Classes are 7pm to 10pm "
            "at 50 Nanyang Avenue, Singapore 639798, and the fee for EE7207 is S$3,270. My password is not working."
        )
        self.assertEqual(self.masked(text), text)

    def test_missing_or_changed_model_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(PrivacyDetectorFailureError):
                DetailDetector(Path(folder))
            for name in ("config.json", "model_q4.onnx", "model_q4.onnx_data", "tokenizer.json"):
                (Path(folder) / name).write_text("{}")
            with self.assertRaises(PrivacyDetectorFailureError):
                DetailDetector(Path(folder))

    def test_overlapping_findings_are_merged_not_dropped(self):
        merged = _deduplicate([PiiFinding("EMAIL", 10, 20, 1.0, "rule"), PiiFinding("PERSON", 5, 12, .75, "model"), PiiFinding("ADDRESS", 30, 40, .75, "model")])
        self.assertEqual([(f.category, f.start, f.end) for f in merged], [("EMAIL", 5, 20), ("ADDRESS", 30, 40)])


class EgressDetailTests(unittest.TestCase):
    def test_structured_details_block(self):
        sentinel = EgressPrivacySentinel()
        for text in (
            "Please send it to [[PII_PERSON_abcdefgh_0001]] at #05-123, Tampines Street 81, 520123.",
            "My address is Clementi Avenue 2, Singapore 120345.",
            "Call me on +60 12-345 6789.",
            "My card is 4539 1488 0343 6467.",
            "Date of birth: 3 March 1990",
        ):
            with self.subTest(text=text):
                self.assertTrue(sentinel.scan_text(text))

    def test_public_details_pass(self):
        sentinel = EgressPrivacySentinel()
        for text in (
            "Our office is at 50 Nanyang Avenue, Singapore 639798.",
            "The January 2027 intake closes on 15/12/2026 and costs S$3,270.00.",
            "Course EE7207 runs 7pm to 10pm.",
        ):
            with self.subTest(text=text):
                self.assertFalse(sentinel.scan_text(text))


if __name__ == "__main__":
    unittest.main()
