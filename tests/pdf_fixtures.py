"""Test PDFs built with reportlab (BSD) and pypdf (BSD)."""

from __future__ import annotations

from io import BytesIO

from pypdf import PdfReader, PdfWriter
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas


def text_pdf(width: float, height: float, lines: list[tuple[float, float, str, float]]) -> bytes:
    """`lines`: (x, baseline from the top, text, font size)."""
    output = BytesIO()
    document = canvas.Canvas(output, pagesize=(width, height))
    for x, y, text, size in lines:
        document.setFont("Helvetica", size)
        document.drawString(x, height - y, text)
    document.showPage(); document.save()
    return output.getvalue()


def image_pdf(width: float, height: float, png: bytes, pages: int = 1) -> bytes:
    """Scanned pages: the image fills each page and there is no text layer."""
    output = BytesIO()
    document = canvas.Canvas(output, pagesize=(width, height))
    for _ in range(pages):
        document.drawImage(ImageReader(BytesIO(png)), 0, 0, width, height)
        document.showPage()
    document.save()
    return output.getvalue()


def blank_pdf(pages: int) -> bytes:
    output = BytesIO()
    document = canvas.Canvas(output)
    for _ in range(pages):
        document.showPage()
    document.save()
    return output.getvalue()


def encrypted_pdf() -> bytes:
    writer = PdfWriter(clone_from=PdfReader(BytesIO(blank_pdf(1))))
    writer.encrypt(user_password="user", owner_password="owner", algorithm="RC4-128")  # RC4 needs no extra package
    output = BytesIO(); writer.write(output)
    return output.getvalue()
