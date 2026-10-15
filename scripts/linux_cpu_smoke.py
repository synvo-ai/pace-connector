"""Linux CPU smoke test; run inside a Linux Python 3.10-3.12 image after installing connector extras."""

from __future__ import annotations

import argparse
from io import BytesIO
from pathlib import Path
import sys

from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
from pdf_fixtures import image_pdf  # noqa: E402
from pace_connector.attachments import LocalAttachmentProcessor
from pace_connector.client import LocalHttpEngineClient
from pace_connector.contracts import AttachmentMetadata, ConnectorInput, LocalAttachment
from pace_connector.privacy import LocalPrivacyDetector
from pace_connector.service import MimePrivacyConnector


def main() -> int:
    arguments = argparse.ArgumentParser()
    arguments.add_argument("--engine-url")
    arguments.add_argument("--api-key")
    options = arguments.parse_args()
    if bool(options.engine_url) != bool(options.api_key):
        return 5
    detector = LocalPrivacyDetector()
    if not detector.find("Dr Jane Doe jane.doe@example.test +65 8123 4567"):
        return 2
    image = Image.new("RGB", (900, 280), "white")
    for candidate in ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/dejavu/DejaVuSans.ttf", "/System/Library/Fonts/Supplemental/Arial.ttf"):
        if Path(candidate).is_file():
            font = ImageFont.truetype(candidate, 32)
            break
    else:
        return 4
    ImageDraw.Draw(image).text((25, 60), "Dr Jane Doe jane.doe@example.test +65 8123 4567", fill="black", font=font)
    png = BytesIO(); image.save(png, format="PNG")
    processor = LocalAttachmentProcessor(detector=detector)
    image_result = processor.process(LocalAttachment(AttachmentMetadata("synthetic.png", "image/png", len(png.getvalue()), "attachment"), png.getvalue()))
    pdf = image_pdf(450, 140, png.getvalue())
    pdf_result = processor.process(LocalAttachment(AttachmentMetadata("synthetic.pdf", "application/pdf", len(pdf), "attachment"), pdf))
    if image_result.status != pdf_result.status or image_result.status != "PRIVACY_VERIFIED":
        return 3
    if options.engine_url:
        result = MimePrivacyConnector(LocalHttpEngineClient(options.engine_url, options.api_key)).process(ConnectorInput(
            raw_eml=b"From: Dr Jane Doe <jane.doe@example.test>\nSubject: Programme enquiry\n\nPlease provide intake information.",
            request_id="rstn_req_00000000000000000000000000000004", correlation_id="rstn_cor_00000000000000000000000000000004", idempotency_key="rstn_idem_00000000000000000000000000000004",
            local_attachments=(LocalAttachment(AttachmentMetadata("synthetic.png", "image/png", len(png.getvalue()), "attachment"), png.getvalue()),),
        ))
        if result.status != "COMPLETED": return 6
    return 0


if __name__ == "__main__":
    sys.exit(main())
