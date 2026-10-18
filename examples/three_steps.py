"""One email through the connector in three steps: mask -> send and receive -> reveal.

  .venv/bin/python examples/three_steps.py examples/graph_with_attachment.json \
      --engine-url <engine URL> --api-key <engine key> [--out three-steps]

Prints each step and writes the evidence to --out, with an index.html to view it:
  1-original.png, 1-masked.png   each image attachment before and after blackout (both stay local)
  1-masked-request.json          exactly what is sent to the engine
  1-placeholders.json            placeholder -> real value (stays local; shown here for the demo only)
  2-engine-result.json           the engine's answer, still with placeholders
  3-revealed-result.json         the same answer with real values put back (stays local)

A .json file is read as a Microsoft Graph message, anything else as a raw .eml.
"""
import argparse
import base64
import html
import json
import re
import secrets
from pathlib import Path

from pace_connector.attachments import LocalAttachmentProcessor
from pace_connector.client import LocalHttpEngineClient
from pace_connector.contracts import ConnectorInput
from pace_connector.masking import LocalPrivacyMasker
from pace_connector.privacy import LocalPrivacyDetector
from pace_connector.service import MimePrivacyConnector

PLACEHOLDER = re.compile(r"\[\[PII_[A-Z_]+_[A-Za-z0-9]+_\d+\]\]")


class KeepSession(LocalPrivacyMasker):
    """The connector's own masker, keeping its session so the demo can show the placeholder map."""

    session = None

    def new_seeded_session(self, seed, known_names=()):
        self.session = super().new_seeded_session(seed, known_names=known_names)
        return self.session


class KeepImages(LocalAttachmentProcessor):
    """Attachment processor that keeps each original and blacked-out image for the demo."""

    images: list = []

    def process(self, attachment):
        result = super().process(attachment)
        KeepImages.images.append((attachment.metadata.filename, attachment.content, result))
        return result


class ShowAndSend:
    """Engine client wrapper: step 1 is printed just before the request leaves, step 2 when the answer arrives."""

    def __init__(self, inner, on_send):
        self.inner, self.on_send = inner, on_send

    def analyse(self, request):
        self.on_send(request)
        return self.inner.analyse(request)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("email", type=Path)
    ap.add_argument("--engine-url", required=True)
    ap.add_argument("--api-key", required=True)
    ap.add_argument("--out", type=Path, default=Path("three-steps"))
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)

    detector = LocalPrivacyDetector()
    masker = KeepSession(detector)
    sent = {}

    def step1(request):
        sent["request"] = request
        msg = request["enquiry"]["currentMessage"]
        print("== Step 1. Mask (on the NTU side) ==")
        print("Subject:", msg["subject"])
        print(msg["body"])
        for item in request["enquiry"]["attachmentEvidence"]:
            print(f'[attachment, {item["processingStatus"]}] {item["excerpt"]}')
        print(f"\n-> sending {len(json.dumps(request))} bytes of masked JSON to the engine; no images, file names or addresses\n")

    connector = MimePrivacyConnector(
        ShowAndSend(LocalHttpEngineClient(a.engine_url, a.api_key, timeout_seconds=120), step1),
        masking_engine=masker,
        attachment_processor=KeepImages(detector=detector),
        privacy_detector=detector,
    )
    is_graph = a.email.suffix == ".json"
    result = connector.process(ConnectorInput(
        raw_eml=b"" if is_graph else a.email.read_bytes(),
        graph_message=a.email.read_bytes() if is_graph else None,
        request_id="rstn_req_" + secrets.token_hex(16),
        correlation_id="rstn_cor_" + secrets.token_hex(16),
        idempotency_key="rstn_idem_" + secrets.token_hex(16),
    ))
    if result.status != "COMPLETED":
        print("connector status:", result.status, result.failure)
        return

    # Step 1 evidence: images, the masked request, the placeholder map.
    images = []
    for n, (name, original, processed) in enumerate(KeepImages.images, start=1):
        (a.out / f"1-original-{n}.png").write_bytes(original)
        for page, png in enumerate(processed.redacted_pages_local_only, start=1):
            (a.out / f"1-masked-{n}-p{page}.png").write_bytes(png)
            images.append((name, original, png, processed.status))
    request_text = json.dumps(sent["request"], indent=1, ensure_ascii=False)
    (a.out / "1-masked-request.json").write_text(request_text)
    placeholders = {p: masker.session.restore(p) for p in sorted(set(PLACEHOLDER.findall(request_text)))}
    (a.out / "1-placeholders.json").write_text(json.dumps(placeholders, indent=1, ensure_ascii=False))

    # Step 2: the engine's answer, still masked.
    engine = result.engine_result["result"]
    (a.out / "2-engine-result.json").write_text(json.dumps(result.engine_result, indent=1, ensure_ascii=False))
    print("== Step 2. Send and receive (the engine sees placeholders only) ==")
    for issue in engine["issues"]:
        print(f'- {issue["issueId"]} {issue["recommendedAction"]:<13} {issue["summary"]}')
    masked_reply = (engine.get("reply") or {}).get("body", "")
    print("\nReply draft as the engine wrote it:\n" + masked_reply)

    # Step 3: real values put back, locally.
    (a.out / "3-revealed-result.json").write_text(json.dumps(result.restored_result, indent=1, ensure_ascii=False))
    revealed_reply = (result.restored_reply or {}).get("body", "")
    print("\n== Step 3. Reveal (on the NTU side) ==")
    for placeholder, value in placeholders.items():
        print(f"  {placeholder} -> {value}")
    print("\nReply draft with real values:\n" + revealed_reply)

    write_page(a.out, sent["request"], placeholders, images, engine, masked_reply, result.restored_result, revealed_reply)
    print(f"\nEvidence and a page to view it: {a.out}/index.html")


def write_page(out, request, placeholders, images, engine, masked_reply, revealed, revealed_reply):
    def mark(text):
        return PLACEHOLDER.sub(lambda m: f"<mark>{m.group(0)}</mark>", html.escape(text))

    def png(data):
        return "data:image/png;base64," + base64.b64encode(data).decode()

    msg = request["enquiry"]["currentMessage"]
    attachments = "".join(f'<p><b>Attachment, {html.escape(e["processingStatus"])}:</b> {mark(e["excerpt"])}</p>' for e in request["enquiry"]["attachmentEvidence"])
    pics = "".join(f'<figure><img src="{png(o)}"><figcaption>{html.escape(n)}: original (stays local)</figcaption></figure><figure><img src="{png(m)}"><figcaption>after blackout, {html.escape(s)} (stays local; only its masked text is sent)</figcaption></figure>' for n, o, m, s in images)
    issues = "".join(f'<li><b>{html.escape(i["recommendedAction"])}</b> {mark(i["summary"])}</li>' for i in engine["issues"])
    revealed_issues = "".join(f'<li><b>{html.escape(i["recommendedAction"])}</b> {html.escape(i["summary"])}</li>' for i in revealed["issues"])
    table = "".join(f"<tr><td><mark>{html.escape(p)}</mark></td><td>{html.escape(v)}</td></tr>" for p, v in placeholders.items())
    page = f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connector in three steps</title>
<style>
:root{{--bg:#fff;--fg:#1d1d1f;--muted:#666;--card:#f5f5f7;--line:#ddd;--mark:#ffe9a8}}
@media (prefers-color-scheme:dark){{:root{{--bg:#151515;--fg:#eee;--muted:#aaa;--card:#222;--line:#333;--mark:#6b5600}}}}
body{{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;max-width:1000px;margin:0 auto;padding:16px}}
section{{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 16px;margin:16px 0}}
pre{{white-space:pre-wrap;word-break:break-word;font:13px/1.45 ui-monospace,monospace}} mark{{background:var(--mark);color:inherit}}
figure{{display:inline-block;margin:8px;max-width:46%;vertical-align:top}} img{{max-width:100%;border:1px solid var(--line)}} figcaption{{color:var(--muted);font-size:13px}}
table{{border-collapse:collapse}} td{{border-bottom:1px solid var(--line);padding:4px 8px;font-size:13px}} .muted{{color:var(--muted)}}
</style></head><body>
<h1>One email through the connector</h1>
<p class="muted">All names, numbers and addresses are made up. Highlighted text is a placeholder.</p>
<section><h2>1. Mask (on the NTU side)</h2>
<p>What the engine receives: subject, body and the attachment's text, masked. No image, file name or address leaves.</p>
<p><b>Subject:</b> {mark(msg["subject"])}</p><pre>{mark(msg["body"])}</pre>{attachments}{pics}</section>
<section><h2>2. Send and receive (the engine sees placeholders only)</h2><ul>{issues}</ul>
<p><b>Reply draft as the engine wrote it:</b></p><pre>{mark(masked_reply)}</pre></section>
<section><h2>3. Reveal (on the NTU side)</h2><table>{table}</table><ul>{revealed_issues}</ul>
<p><b>Reply draft with real values:</b></p><pre>{html.escape(revealed_reply)}</pre></section>
</body></html>
"""
    (out / "index.html").write_text(page)


if __name__ == "__main__":
    main()
