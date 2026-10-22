# PaCE connector

The privacy connector for the NTU PaCE enquiry engine. It runs inside the NTU/RSTN network, next to the email system. For each email it:

1. reads the email: a Microsoft Graph message (JSON) or a raw `.eml`;
2. reads attachments locally: PNG and JPEG with on-device OCR, PDF from the text layer or OCR;
3. masks personal details: names, addresses, dates of birth, email addresses, phone numbers, NRIC/FIN, passport, student, bank and card numbers, links to a person's own pages, passwords and reference numbers become placeholders such as `[[PII_PERSON_…_0001]]` or `[[PII_ADDRESS_…_0001]]`, and personal details in images are blacked out and read again to check;
4. checks the outgoing request a second time, and sends nothing if a personal detail is still visible;
5. sends only the masked request to the engine;
6. puts the real values back into the engine's result, locally.

Raw email, attachments, sender details and the placeholder map never leave the connector. Anything it cannot handle safely comes back as `REQUIRES_MANUAL_HANDLING` with a reason code instead of being sent.

## Install

Python 3.10–3.12, CPU only, Linux or macOS. The connector process uses up to about 3 GB of memory (allow 4 GB) and about 4 GB of disk. Nothing is downloaded at run time.

```
python3 -m venv .venv
.venv/bin/pip install --extra-index-url https://download.pytorch.org/whl/cpu "pace-connector @ git+https://github.com/synvo-ai/pace-connector.git"
```

From a checkout: `.venv/bin/pip install --extra-index-url https://download.pytorch.org/whl/cpu -e .` (add `[test]` to run the tests). The extra index gives the CPU build of PyTorch, which the name model needs; without it pip installs a much larger GPU build that the connector does not use.

The OCR models ship inside the package and the name model is installed with it. The **detail model** (addresses, dates of birth and numbers; about 0.9 GB) is supplied by Synvo as a folder of four files. Put it in `~/.cache/pace-connector/detail-model`, or set `PACE_DETAIL_MODEL_DIR` to its folder. The connector checks each file against a pinned digest, and does not start masking without it.

## Run as a local HTTP service

```
export PACE_ENGINE_API_KEY=<engine key issued by Synvo>
export PACE_CONNECTOR_NONCE_SECRET=<random string, 16+ characters, kept the same across restarts (required)>
export PACE_CONNECTOR_API_KEY=<optional: key your system must send to the connector>
.venv/bin/python -m pace_connector.server --engine-url <engine URL> --port 8788
```

Options: `--host` (default `127.0.0.1`), `--port` (default `8788`), `--engine-url` (or `PACE_ENGINE_URL`), `--engine-timeout` in seconds (default 120), `--mailbox` (or `PACE_MAILBOX_ADDRESSES`: PaCE's own addresses, comma-separated, used for follow-ups below), `--show-masked` (testing only: adds the exact masked request to each answer).

### `POST /v0/messages`

Send one email per request:

- `Content-Type: application/json`: one Microsoft Graph message, as returned by `GET /users/{id}/messages/{id}`. Add `?$expand=attachments` when you fetch it if attachments should be read.
- `Content-Type: message/rfc822`: one raw `.eml`.
- If `PACE_CONNECTOR_API_KEY` is set, send it as `x-api-key`.

```
curl -s -H 'content-type: application/json' -H 'x-api-key: <connector key>' \
  --data-binary @examples/graph_message.json http://127.0.0.1:8788/v0/messages
```

### Follow-ups

On a follow-up, the quoted history in the body is cut and not sent. Send the earlier messages of the conversation, and the issues from earlier results, in an envelope instead (`application/json`):

```
{
  "message": { ...the new Graph message... },
  "thread": [
    {"message": { ...earlier Graph message... }},
    {"direction": "STAFF", "message": { ... }},
    {"direction": "USER", "body": "plain text of an earlier message"}
  ],
  "priorIssues": [ { "summary": "...", "missingInformation": ["..."] } ]
}
```

- **`message`:** the new message. Use `"eml": "<base64>"` instead for a raw `.eml`.
- **`thread`:** the earlier messages, oldest first. Get them from Graph with `GET /users/{id}/messages?$filter=conversationId eq '<conversationId>'`, without the new message.
  - Each item is a Graph message (`message`), a base64 `.eml` (`eml`) or plain text (`body`). Only each message's own new text is used, since its quote repeats older messages. Attachments of earlier messages are not read, so fetch them without `$expand=attachments`.
  - **`direction`:** `USER` for the enquirer, `STAFF` for PaCE. It can be left out for Graph and `.eml` items if the connector is started with `--mailbox` (or `PACE_MAILBOX_ADDRESSES`) listing PaCE's own addresses: messages from those addresses count as `STAFF`.
  - **Limit:** the newest 30 messages are kept, and up to 20,000 characters of each.
- **`priorIssues`:** the `issues` from earlier results for this conversation, as returned. Only `summary` (and `missingInformation`, if present) is used; other fields are ignored. Up to 24.
- **Masking:** thread messages and earlier issues are masked like the new message. A person gets the same placeholder everywhere, and the names in the thread messages' From/To are masked too.
- **Resends:** an identical envelope replays the first answer. The same email with a different thread or different issues is analysed again.
- **Errors:** a malformed envelope returns HTTP 400 with `INVALID_ENVELOPE` and the reason.

`examples/graph_followup.json` is a complete example: the new message only says "this course", and the course is named in the thread.

Every processed email returns HTTP 200:

```
{
  "schemaVersion": "pace-connector-http-v0",
  "status": "COMPLETED" | "REQUIRES_MANUAL_HANDLING",
  "failure": null | {"code": "...", "message": "..."},
  "message": {"id": "...", "internetMessageId": "...", "conversationId": "..."},
  "result": { ... the engine's result, with real names put back ... },
  "reply": {"subject": "...", "body": "..."} | null
}
```

- `message` echoes the Graph identifiers so you can match the answer to the email.
- `result` and `reply` contain personal details again: keep them inside your network.
- Other status codes concern the HTTP call itself: 400 (malformed follow-up envelope), 401 (wrong `x-api-key`), 404, 413 (over 50 MB), 415 (wrong content type).

`GET /v0/health` returns `{"status": "ok", ...}`.

### Resending

Sending the same email again (same Graph `id`, or the same `Message-ID` for `.eml`) produces the identical masked request, so the engine returns its first answer instead of processing the email twice. This holds across restarts only if `PACE_CONNECTOR_NONCE_SECRET` stays the same.

### Failure codes

| Code | Meaning |
|---|---|
| `MALFORMED_EMAIL`, `BODY_UNAVAILABLE` | The email could not be parsed, or has no readable body. |
| `REQUEST_LIMIT_EXCEEDED`, `ATTACHMENT_LIMIT_EXCEEDED` | Over a size limit (25 MB email, 40,000-character body, 24 attachments). |
| `PRIVACY_SCOPE_UNSUPPORTED` | Text in a non-Latin script. English emails only for now. |
| `MASKING_FAILURE`, `PRIVACY_DETECTOR_FAILURE` | Masking could not run. |
| `EGRESS_PRIVACY_CHECK_FAILED` | The second check still saw a personal detail, so nothing was sent. |
| `ENGINE_UNAVAILABLE`, `RATE_LIMITED` | The engine could not be reached or asked to slow down. |
| `AUTHENTICATION_FAILURE`, `ENGINE_CONTRACT_REJECTED`, `IDEMPOTENCY_CONFLICT`, `DELIVERY_CONFIGURATION` | Key, version or configuration problems between the connector and the engine. |
| `INTERNAL_CONNECTOR_ERROR` | Anything unexpected. |

An attachment that cannot be read safely does not stop the email; it is sent as "attachment present, not read". Attachments are read up to 8 MB each, 10 pages and 45 seconds; larger images are scaled down to 4000 pixels first.

## Use as a library

```python
from pace_connector.client import LocalHttpEngineClient
from pace_connector.contracts import ConnectorInput
from pace_connector.server import message_ids
from pace_connector.service import MimePrivacyConnector

connector = MimePrivacyConnector(LocalHttpEngineClient("<engine URL>", "<engine key>", timeout_seconds=120))
result = connector.process(ConnectorInput(b"", **message_ids("graph:" + graph_id), graph_message=graph_json_bytes))
# result.status, result.failure, result.restored_result, result.restored_reply
```

`examples/three_steps.py` shows one email in three steps, mask, send and receive, reveal, and writes the evidence (the image before and after blackout, the exact masked request, the engine's answer, the revealed result) with an `index.html` to view it:

```
.venv/bin/python examples/three_steps.py examples/graph_with_attachment.json --engine-url <engine URL> --api-key <engine key> --out three-steps
```

`examples/run_one.py` runs one email and prints each step:

```
.venv/bin/python examples/run_one.py examples/graph_with_attachment.json --engine-url <engine URL> --api-key <engine key>
```

## What is masked, and limits

- **Structural details:** email addresses, Singapore phone numbers, NRIC/FIN, NTU matriculation numbers, and reference codes such as payment, receipt and application numbers (capitals and hyphens with a group of 3+ digits, e.g. `PAY-2026-0042`); a student, passport or account number after its label; a password after "password".
- **Other personal details:** a local detail model finds addresses in any country, dates of birth, passport, bank and card numbers, phone numbers from other countries, email addresses written in words, links to a person's own pages (LinkedIn, GitHub) and passwords. Public details stay readable: a date counts only after "date of birth", "DOB" or "born", so intake dates and deadlines stay; PaCE's and NTU's own addresses stay (`PUBLIC_POSTAL_CODES` in `pace_connector/details.py`); course codes stay.
- **Names:** a local English name recogniser (spaCy, transformer model), plus rules:
  - names in name positions: after "Dear", in a sign-off, after "my name is", in a "Name:" field, after a title;
  - name-shaped words: capitalised words in a row that are not ordinary English;
  - the sender's and recipients' own names from the email envelope.
- **Names that are also ordinary English words,** written alone with no cue ("please pass my thanks to Hope"), can be missed.
- **Second check:** before sending, the request is checked again without the models, by rules: names in name positions, structural details, and addresses with a unit number or postal code, phone numbers with a country code, dates after "date of birth", and card numbers.
- **Programme titles:** a Title Case programme title containing a word the connector does not know can be masked as a name. Add such words to `pace_connector/public_words.txt`.
- **English only.** Text in other scripts is not sent; the email goes to manual handling.
- **Follow-ups:** quoted history in the body is cut and not sent. Without an envelope, the engine sees only the newest message.

How these were measured: `benchmarks/README.md`.

## Tests

```
.venv/bin/pip install --extra-index-url https://download.pytorch.org/whl/cpu -e ".[test]"
PYTHONPATH=.:tests .venv/bin/python -m pytest -q tests
```

Two tests of the optional Paddle OCR backend are skipped unless it is installed (`pip install -e ".[paddle]"`). The default OCR does not need it.

## Licence

Copyright © 2026 Synvo AI. Licensed only for use with the NTU PaCE enquiry system; see `LICENSE`. Third-party components keep their own licences; see `THIRD_PARTY_NOTICES.md`.
