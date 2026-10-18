import unittest

from pace_connector.privacy import LocalPrivacyDetector


class ReferenceCodeTests(unittest.TestCase):
    def found(self, text):
        return [(f.category, text[f.start:f.end]) for f in LocalPrivacyDetector().find(text)]

    def test_payment_and_receipt_codes_are_masked(self):
        self.assertEqual(self.found("Reference: PAY-2026-0042"), [("REFERENCE", "PAY-2026-0042")])
        self.assertEqual(self.found("My payment reference is PACE-GCADA-2026-11903."), [("REFERENCE", "PACE-GCADA-2026-11903")])

    def test_programme_codes_dates_and_amounts_are_not(self):
        self.assertEqual(self.found("The GC-ADA programme starts on 2026-01-11 and costs S$500.00."), [])


if __name__ == "__main__":
    unittest.main()
