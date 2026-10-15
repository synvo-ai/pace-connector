# PaCE connector

The privacy connector for the NTU PaCE enquiry engine. It runs inside the NTU/RSTN network, next to the email system. For each email it:

1. reads the email: a Microsoft Graph message (JSON) or a raw `.eml`;
2. reads attachments locally: PNG and JPEG with on-device OCR, PDF from the text layer or OCR;
3. masks personal details: names, email addresses, phone numbers, NRIC/FIN and reference numbers become placeholders such as `[[PII_PERSON_…_0001]]`, and personal details in images are blacked out and read again to check;
4. checks the outgoing request a second time, and sends nothing if a personal detail is still visible;
5. sends only the masked request to the engine;
6. puts the real values back into the engine's result, locally.

Raw email, attachments, sender details and the placeholder map never leave the connector. Anything it cannot handle safely comes back as `REQUIRES_MANUAL_HANDLING` with a reason code instead of being sent.

`connector_walk_through.html` follows one email through every step.

## Install

Python 3.10–3.12, CPU only, Linux or macOS. The OCR model files ship inside the package; nothing is downloaded at run time except the dependencies themselves.

```
python3 -m venv .venv
.venv/bin/pip install "pace-connector @ git+https://github.com/synvo-ai/pace-connector.git"
```

From a checkout: `.venv/bin/pip install -e .` (add `[test]` to run the tests).

## Run as a local HTTP service

```
export PACE_ENGINE_API_KEY=<engine key issued by Synvo>
export PACE_CONNECTOR_NONCE_SECRET=<long random string, kept the same across restarts>
export PACE_CONNECTOR_API_KEY=<optional: key your system must send to the connector>
.venv/bin/python -m pace_connector.server --engine-url <engine URL> --port 8788
```

Options: `--host` (default `127.0.0.1`), `--port` (default `8788`), `--engine-url` (or `PACE_ENGINE_URL`), `--engine-timeout` in seconds (default 120), `--show-masked` (testing only: adds the exact masked request to each answer).

### `POST /v0/messages`

Send one email per request:

- `Content-Type: application/json`: one Microsoft Graph message, as returned by `GET /users/{id}/messages/{id}`. Add `?$expand=attachments` when you fetch it if attachments should be read.
- `Content-Type: message/rfc822`: one raw `.eml`.
- If `PACE_CONNECTOR_API_KEY` is set, send it as `x-api-key`.

```
curl -s -H 'content-type: application/json' -H 'x-api-key: <connector key>' \
  --data-binary @examples/graph_message.json http://127.0.0.1:8788/v0/messages
```

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
- Other status codes concern the HTTP call itself: 401 (wrong `x-api-key`), 404, 413 (over 512 KB), 415 (wrong content type).

`GET /v0/health` returns `{"status": "ok", ...}`.

### Resending

Sending the same email again (same Graph `id`, or the same `Message-ID` for `.eml`) produces the identical masked request, so the engine returns its first answer instead of processing the email twice. This holds across restarts only if `PACE_CONNECTOR_NONCE_SECRET` stays the same.

### Failure codes

| Code | Meaning |
|---|---|
| `MALFORMED_EMAIL`, `BODY_UNAVAILABLE` | The email could not be parsed, or has no readable body. |
| `REQUEST_LIMIT_EXCEEDED`, `ATTACHMENT_LIMIT_EXCEEDED` | Over a size limit (256 KB email, 40,000-character body, 24 attachments). |
| `PRIVACY_SCOPE_UNSUPPORTED` | Text in a non-Latin script. English emails only for now. |
| `MASKING_FAILURE`, `PRIVACY_DETECTOR_FAILURE` | Masking could not run. |
| `EGRESS_PRIVACY_CHECK_FAILED` | The second check still saw a personal detail, so nothing was sent. |
| `ENGINE_UNAVAILABLE`, `RATE_LIMITED` | The engine could not be reached or asked to slow down. |
| `AUTHENTICATION_FAILURE`, `ENGINE_CONTRACT_REJECTED`, `IDEMPOTENCY_CONFLICT`, `DELIVERY_CONFIGURATION` | Key, version or configuration problems between the connector and the engine. |
| `INTERNAL_CONNECTOR_ERROR` | Anything unexpected. |

An attachment that cannot be read safely does not stop the email; it is sent as "attachment present, not read".

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

`examples/run_one.py` runs one email and prints each step:

```
.venv/bin/python examples/run_one.py examples/graph_with_attachment.json --engine-url <engine URL> --api-key <engine key>
```

## What is masked, and limits

- **Structural details:** email addresses, Singapore phone numbers, NRIC/FIN, and prefixed application, reference, account and payment numbers.
- **Names:** a local English name recogniser (spaCy), plus rules:
  - names in name positions: after "Dear", in a sign-off, after "my name is", in a "Name:" field, after a title;
  - name-shaped words: capitalised words in a row that are not ordinary English;
  - the sender's and recipients' own names from the email envelope.
- **Names that are also ordinary English words,** written alone with no cue ("please ask Hope"), can be missed.
- **Programme titles:** a Title Case programme title containing a word the connector does not know can be masked as a name. Add such words to `pace_connector/public_words.txt`.
- **English only.** Text in other scripts is not sent; the email goes to manual handling.
- **Follow-ups:** quoted history in the body is cut and not sent, so on a follow-up the engine sees the newest message.

How these were measured: `benchmarks/README.md`.

## Tests

```
.venv/bin/pip install -e ".[test]"
PYTHONPATH=.:tests .venv/bin/python -m pytest -q tests
```

Two tests of the optional Paddle OCR backend are skipped unless it is installed (`pip install -e ".[paddle]"`). The default OCR does not need it.

## Licence

Copyright © 2026 Synvo AI. Licensed only for use with the NTU PaCE enquiry system; see `LICENSE`. Third-party components keep their own licences; see `THIRD_PARTY_NOTICES.md`.
