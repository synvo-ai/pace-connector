"""Executable privacy failure matrix; every row has an assertion."""

from __future__ import annotations

from io import BytesIO
import unittest
from unittest.mock import patch

from PIL import Image

from pace_connector.attachments import LocalAttachmentProcessor, OcrToken, _align
from pace_connector.contracts import AttachmentMetadata, ConnectorInput, LocalAttachment
from pace_connector.errors import PrivacyDetectorFailureError, PrivacyScopeUnsupportedError
from pace_connector.masking import LocalPrivacyMasker, MaskingResult
from pace_connector.privacy import EgressPrivacyGate, EgressPrivacySentinel, LocalPrivacyDetector
from pace_connector.service import MimePrivacyConnector


RAW = b"From: Alice Example <alice@example.test>\nSubject: Programme enquiry\n\nDr Jane Doe asks about intake."


class RecordingClient:
    def __init__(self): self.calls: list[dict] = []
    def analyse(self, payload):
        self.calls.append(payload)
        message = payload["enquiry"]["currentMessage"]
        return {"result": {"reply": {"status": "AVAILABLE", "subject": message["subject"], "body": message["body"]}}}


class MissDetector:
    def find(self, _text): return ()


class BrokenDetector:
    def find(self, _text): raise PrivacyDetectorFailureError()


class LeakySession:
    def mask(self, text): return MaskingResult(text, ())
    def restore(self, text): return text


class LeakyMasker:
    def new_session(self): return LeakySession()


class ThrowingSentinel:
    def scan_text(self, _text, *, include_person=True): raise PrivacyDetectorFailureError()
    def validate_identifier(self, _value): raise PrivacyDetectorFailureError()


class Tokens:
    def __init__(self, *responses): self.responses = list(responses)
    def read(self, _image):
        response = self.responses.pop(0)
        if isinstance(response, Exception): raise response
        return response


def token(text: str, confidence: float = 1.0, polygon=((.1, .1), (.5, .1), (.5, .2), (.1, .2))):
    return OcrToken(text, 0, polygon, confidence)


def attachment() -> LocalAttachment:
    image = Image.new("RGB", (600, 240), "white")
    stream = BytesIO(); image.save(stream, format="PNG")
    return LocalAttachment(AttachmentMetadata("synthetic.png", "image/png", len(stream.getvalue()), "attachment"), stream.getvalue())


def input_for(**updates) -> ConnectorInput:
    values = {"raw_eml": RAW, "request_id": "rstn_req_00000000000000000000000000000003", "correlation_id": "rstn_cor_00000000000000000000000000000003", "idempotency_key": "rstn_idem_00000000000000000000000000000003"}
    values.update(updates)
    return ConnectorInput(**values)


class PrivacyFailureMatrix(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.detector = LocalPrivacyDetector()

    def _connector(self, **kwargs):
        client = RecordingClient()
        return client, MimePrivacyConnector(client, **kwargs)

    def _assert_blocked(self, identifier: str, connector: MimePrivacyConnector, client: RecordingClient, value: ConnectorInput = input_for()):
        result = connector.process(value)
        with self.subTest(matrix=identifier):
            self.assertEqual(result.status, "REQUIRES_MANUAL_HANDLING")
            self.assertEqual(client.calls, [])

    def test_text_and_egress_rows_p01_to_p15(self) -> None:
        # P01/P02/P04: primary PERSON/structural miss cannot cross egress.
        for row, body in (("P01", b"Professor Maria-Louise Tan asks about intake."), ("P02", b"Email jane@example.test asks about intake."), ("P04", b"Dr Jane Doe asks about intake.")):
            client, connector = self._connector(masking_engine=LeakyMasker(), privacy_detector=MissDetector())
            self._assert_blocked(row, connector, client, input_for(raw_eml=RAW.split(b"\n\n")[0] + b"\n\n" + body))
        # P03: primary exception stops before HTTP.
        client, connector = self._connector(privacy_detector=BrokenDetector())
        self._assert_blocked("P03", connector, client)
        # P05: independent sentinel exception is fail-closed.
        client, connector = self._connector(egress_gate=EgressPrivacyGate(ThrowingSentinel()))
        self._assert_blocked("P05", connector, client)
        # P06/P07: NFKC and format characters reveal a structural leak.
        gate = EgressPrivacyGate()
        for row, value in (("P06", "jane＠example.com"), ("P07", "jane@exam\u200bple.com")):
            with self.subTest(matrix=row):
                with self.assertRaises(Exception): gate.validate({"requestId": "safe-1", "correlationId": "safe-2", "idempotencyKey": "safe-3", "enquiry": {"currentMessage": {"subject": "x", "body": value}, "permittedThread": [], "priorIssues": [], "attachmentEvidence": []}})
        # P08/P09/P10: non-Latin alphabetic scripts are not silently clean.
        for row, value in (("P08", "ภาษาไทย"), ("P09", "देवनागरी"), ("P10", "Հայերեն"), ("SCOPE-CHINESE", "中文"), ("SCOPE-ARABIC", "العربية"), ("SCOPE-HANGUL", "한글"), ("SCOPE-JAPANESE", "日本語")):
            with self.subTest(matrix=row):
                with self.assertRaises(PrivacyScopeUnsupportedError): self.detector.find(value)
        self.assertTrue(self.detector.find("Dr Élodie Martin"))
        self.assertEqual(self.detector.find("$1,200 / 2026-05-01 !?"), ())
        # P11 exact business entity passes; P12 exact-span allowlisting must
        # not erase a substring inside a real person-like value.
        self.assertFalse(EgressPrivacySentinel().scan_text("Nanyang Technological University"))
        sentinel = EgressPrivacySentinel()
        for value in ("JANE DOE", "jane doe", "Jane DOE", "J. Doe", "J Doe", "MARIA-LOUISE TAN", "maria-louise tan", "O'NEILL CLARA", "Space Lee", "Pace Tan", "Grace Pace Lee"):
            with self.subTest(person=value): self.assertTrue(sentinel.scan_text(value))
        for value in ("Space Lee", "Pace Tan", "Grace Pace Lee"):
            client, connector = self._connector(masking_engine=LeakyMasker(), privacy_detector=MissDetector())
            self._assert_blocked("P12", connector, client, input_for(raw_eml=RAW.split(b"\n\n")[0] + b"\n\n" + value.encode("ascii") + b" asks about intake."))
        # NQ-R1 regression: a sender name adjacent to a document reference is
        # still caught by the independent residual-person sentinel.
        self.assertTrue(sentinel.scan_text("Jane Doe reference DOC-8271"))
        # P13/P14/P15: outbound opaque IDs cannot carry structural PII.
        for row, key, value in (("P13", "request_id", "jane@example.test"), ("P14", "correlation_id", "+65-3123-4567"), ("P15", "idempotency_key", "S1234567A")):
            client, connector = self._connector()
            self._assert_blocked(row, connector, client, input_for(**{key: value}))
        client, connector = self._connector()
        self._assert_blocked("ID-WHITESPACE", connector, client, input_for(request_id="not opaque"))
        for value in ("Jane.Doe", "Space.Lee", "JANE.DOE"):
            client, connector = self._connector()
            self._assert_blocked("ID-HUMAN-PAYLOAD", connector, client, input_for(request_id=value))
        client, connector = self._connector()
        self.assertEqual(connector.process(input_for()).status, "COMPLETED")
        self.assertEqual(len(client.calls), 1)

    def test_attachment_rows_p16_to_p26(self) -> None:
        # P16 zero OCR, P17 sparse/low confidence, P18 exception all fail closed.
        cases = (
            ("P16", Tokens([]), "PRIVACY_UNCERTAIN"),
            ("P17", Tokens([token("Receipt", .1)]), "PRIVACY_UNCERTAIN"),
            ("P18", Tokens(RuntimeError("ocr unavailable")), "OCR_FAILED"),
        )
        for row, engine, status in cases:
            with self.subTest(matrix=row):
                result = LocalAttachmentProcessor(ocr_engine=engine, detector=self.detector).process(attachment())
                self.assertEqual(result.status, status)
                self.assertFalse(result.raw_text_local_only)
        # P19 OCR-spaced NRIC is explicitly detected and geometrically mapped;
        # the later zero-token verifier is independently what makes it uncertain.
        spaced = [token("S 1234567 A"), token("Receipt")]
        joined = " ".join(item.text for item in spaced)
        nric = [item for item in self.detector.find(joined) if item.category == "NRIC_FIN"]
        self.assertTrue(nric)
        self.assertTrue(_align([(item.start, item.end) for item in nric], spaced, .5))
        self.assertEqual(LocalAttachmentProcessor(ocr_engine=Tokens(spaced, []), detector=self.detector).process(attachment()).status, "PRIVACY_UNCERTAIN")
        # Unicode/full-width and split structural adversaries are either found
        # under NFKC or rejected as outside the ASCII-number scope.
        for value, category in (("＋６５　８１２３　４５６７", "PHONE"), ("+65 8 1 2 3 4 5 6 7", "PHONE"), ("Application: APP 2026 001", "REFERENCE"), ("Reference REF CASE 001", "REFERENCE")):
            with self.subTest(adversary=value): self.assertIn(category, {item.category for item in self.detector.find(value)})
        with self.assertRaises(PrivacyScopeUnsupportedError): self.detector.find("+٦٥ ٨١٢٣ ٤٥٦٧")
        malformed = [token("Alice Example", polygon=()), token("Receipt")]
        self.assertNotEqual(LocalAttachmentProcessor(ocr_engine=Tokens(malformed), detector=self.detector).process(attachment()).status, "PRIVACY_VERIFIED")
        # P21 redaction error, P22 residual, P23 empty verification all fail closed.
        with patch("pace_connector.attachments._redact", side_effect=RuntimeError("redaction failure")):
            self.assertEqual(LocalAttachmentProcessor(ocr_engine=Tokens([token("Alice Example"), token("Receipt")]), detector=self.detector).process(attachment()).status, "REDACTION_FAILED")
        residual = [token("Alice Example"), token("Receipt")]
        self.assertEqual(LocalAttachmentProcessor(ocr_engine=Tokens(residual, residual), detector=self.detector).process(attachment()).status, "REDACTION_VERIFICATION_FAILED")
        self.assertEqual(LocalAttachmentProcessor(ocr_engine=Tokens(residual, []), detector=self.detector).process(attachment()).status, "PRIVACY_UNCERTAIN")
        # P24 sender attachment failure stays metadata-only while safe body analysis continues.
        client, connector = self._connector()
        result = connector.process(input_for(local_attachments=(LocalAttachment(AttachmentMetadata("bad.bin", "application/octet-stream", 3, "attachment"), b"bad"),)))
        self.assertEqual(result.status, "COMPLETED"); self.assertEqual(len(client.calls), 1)
        self.assertEqual(result.canonical_request["enquiry"]["attachmentEvidence"][0]["contentState"], "NOT_READ")
        # P25 mixed locally unsafe and metadata-only attachment evidence stays non-readable.
        client, connector = self._connector()
        result = connector.process(input_for(
            local_attachments=(LocalAttachment(AttachmentMetadata("bad.bin", "application/octet-stream", 3, "attachment"), b"bad"),),
            externally_observed_attachments=(AttachmentMetadata("observed.pdf", "application/pdf", 1, "attachment"),),
        ))
        self.assertEqual(result.status, "COMPLETED"); self.assertEqual(len(client.calls), 1)
        self.assertTrue(all(item["contentState"] in {"NOT_READ", "METADATA_ONLY"} for item in result.canonical_request["enquiry"]["attachmentEvidence"]))
        # P26 attachment-local detector miss fails closed, while the separately
        # safe body is still allowed to reach the engine as metadata-only.
        result = LocalAttachmentProcessor(ocr_engine=Tokens(residual, residual), detector=MissDetector()).process(attachment())
        self.assertEqual(result.status, "REDACTION_VERIFICATION_FAILED")
        client, connector = self._connector(attachment_processor=LocalAttachmentProcessor(ocr_engine=Tokens(residual, residual), detector=MissDetector()))
        result = connector.process(input_for(local_attachments=(attachment(),)))
        self.assertEqual(result.status, "COMPLETED")
        self.assertEqual(len(client.calls), 1)
        evidence = result.canonical_request["enquiry"]["attachmentEvidence"][0]
        self.assertEqual(evidence["processingStatus"], "REDACTION_VERIFICATION_FAILED")
        self.assertNotIn("Alice Example", str(result.canonical_request))

    def test_remaining_rows_p27_to_p30(self) -> None:
        # P27 direct canonical leak injection is caught before transport.
        with self.assertRaises(Exception):
            EgressPrivacyGate().validate({"requestId": "safe-1", "correlationId": "safe-2", "idempotencyKey": "safe-3", "enquiry": {"currentMessage": {"subject": "x", "body": "jane@example.test"}, "permittedThread": [], "priorIssues": [], "attachmentEvidence": []}})
        # P28 unavailable detector model cannot silently fall back.
        with self.assertRaises(PrivacyDetectorFailureError): LocalPrivacyDetector("missing_local_model")
        # P29 placeholders do not restore across requests.
        first, second = LocalPrivacyMasker(self.detector).new_session(), LocalPrivacyMasker(self.detector).new_session()
        placeholder = first.mask("Alice Example").masked_text
        self.assertNotEqual(placeholder, second.mask("Alice Example").masked_text)
        self.assertEqual(second.restore(placeholder), placeholder)
        # P30 typed failure contains no raw input and no HTTP call.
        client, connector = self._connector(privacy_detector=BrokenDetector())
        result = connector.process(input_for())
        self.assertNotIn("Alice", result.failure.message)
        self.assertEqual(client.calls, [])

    def test_q2_rows_p31_to_p40(self) -> None:
        sentinel = EgressPrivacySentinel()
        # P31/P32: short Asian and diacritic names reproduced from independent
        # review are caught by the independent residual policy, not a name list.
        for row, value in (("P31", "Li Kai"), ("P32", "José García")):
            with self.subTest(matrix=row):
                self.assertTrue(sentinel.scan_text(value))
                client, connector = self._connector(masking_engine=LeakyMasker(), privacy_detector=MissDetector())
                self._assert_blocked(row, connector, client, input_for(raw_eml=RAW.split(b"\n\n")[0] + b"\n\n" + value.encode("utf-8")))
        # P33-P36: ordinary Title Case business correspondence remains usable
        # and reaches the recording client; it is not masked as PERSON.
        for row, value in (("P33", "Programme Details"), ("P34", "Dear Team"), ("P35", "Application Status 2026"), ("P36", "Payment status: amount 1200")):
            with self.subTest(matrix=row):
                self.assertFalse(sentinel.scan_text(value))
                client, connector = self._connector()
                result = connector.process(input_for(raw_eml=b"Subject: " + value.encode() + b"\n\n" + value.encode()))
                self.assertEqual(result.status, "COMPLETED")
                self.assertEqual(len(client.calls), 1)
                self.assertEqual(result.canonical_request["enquiry"]["currentMessage"]["body"], value)
        # P37: synthetic ID grammar masks exactly the token, never the prose.
        sample = "SYN-ABC-123 asks about intake"
        finding = [item for item in self.detector.find(sample) if item.category == "SYNTHETIC_ID"]
        self.assertEqual(len(finding), 1)
        self.assertEqual(sample[finding[0].start:finding[0].end], "SYN-ABC-123")
        self.assertFalse(self.detector.find("Application Status 2026"))
        self.assertTrue(self.detector.find("Application: APP 2026 001"))
        # P38: attachment observation (not just excerpt) is content-scanned;
        # a sender-provided observation cannot bypass the final gate.
        client, connector = self._connector()
        completed = connector.process(input_for())
        self.assertEqual(completed.status, "COMPLETED")
        payload = completed.canonical_request
        payload["enquiry"]["attachmentEvidence"] = [{
            "attachmentId": "mime-attachment-001", "pageNumber": None, "section": "mime-metadata",
            "excerpt": "safe", "observation": "José García", "extractionMethod": "NONE",
            "provider": "python-mime-connector-m2-b", "relevance": 0, "provenance": "SENDER_PROVIDED",
            "privacyTransformation": "CONNECTOR_MASKED", "contentState": "NOT_READ", "processingStatus": "NOT_READ",
        }]
        with self.assertRaises(Exception): EgressPrivacyGate().validate(payload)
        # P39: a future outbound string without a policy is a fail-closed
        # contract drift, even when it contains no apparent PII.
        payload["enquiry"]["attachmentEvidence"][0]["observation"] = "safe"
        payload["enquiry"]["futureString"] = "ordinary text"
        with self.assertRaises(Exception): EgressPrivacyGate().validate(payload)
        # P40: a final held-out residual still blocks raw canonical egress.
        with self.assertRaises(Exception):
            EgressPrivacyGate().validate({"requestId": "safe-1", "correlationId": "safe-2", "idempotencyKey": "safe-3", "enquiry": {"currentMessage": {"messageId": "current-message", "subject": "programme", "body": "Émile Laurent"}, "permittedThread": [], "priorIssues": [], "attachmentEvidence": []}})


if __name__ == "__main__": unittest.main()
