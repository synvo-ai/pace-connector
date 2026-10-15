"""Run one email through the connector and show each step.

  .venv/bin/python examples/run_one.py examples/scholarship.eml \
      --engine-url <engine URL> --api-key <engine key>

A .json file is read as a Microsoft Graph message (examples/graph_message.json).
"""
import argparse
import json
import secrets
from pathlib import Path

from pace_connector.client import LocalHttpEngineClient
from pace_connector.contracts import ConnectorInput
from pace_connector.service import MimePrivacyConnector


def opaque(prefix: str) -> str:
    # The connector only accepts machine IDs: prefix + 32 lowercase hex characters.
    return prefix + secrets.token_hex(16)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("eml", type=Path)
    ap.add_argument("--engine-url", required=True)
    ap.add_argument("--api-key", required=True)
    a = ap.parse_args()

    connector = MimePrivacyConnector(LocalHttpEngineClient(a.engine_url, a.api_key, timeout_seconds=60))
    is_graph = a.eml.suffix == ".json"
    result = connector.process(ConnectorInput(
        raw_eml=b"" if is_graph else a.eml.read_bytes(),
        graph_message=a.eml.read_bytes() if is_graph else None,
        request_id=opaque("rstn_req_"),
        correlation_id=opaque("rstn_cor_"),
        idempotency_key=opaque("rstn_idem_"),  # reuse the same key when retrying the same email
    ))

    print("== connector status:", result.status, result.failure or "")
    if result.canonical_request:
        msg = result.canonical_request["enquiry"]["currentMessage"]
        print("\n== what leaves NTU (masked) ==\nSubject:", msg["subject"], "\n" + msg["body"])
        for item in result.canonical_request["enquiry"]["attachmentEvidence"]:
            print(f'[attachment {item["processingStatus"]}] {item["excerpt"]}')
    if result.engine_result:
        r = result.engine_result["result"]
        print("\n== engine result ==")
        print("run:", json.dumps(r["run"]))
        for issue in result.restored_result["issues"]:  # names restored, stays at NTU
            print(f'- {issue["issueId"]} {issue["recommendedAction"]:<13} {issue["summary"]}')
        print("verification:", r["verification"]["status"])
    if result.restored_reply:
        print("\n== reply draft with names restored (stays at NTU) ==\n" + result.restored_reply["body"])


if __name__ == "__main__":
    main()
