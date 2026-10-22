"""Download the detail model (about 0.9 GB) into the folder the connector reads.

    python -m pace_connector.fetch_model [target folder]

Default target: `PACE_DETAIL_MODEL_DIR`, else `~/.cache/pace-connector/detail-model`. The files come from
the `detail-model-v1` release of synvo-ai/pace-connector, or from `PACE_DETAIL_MODEL_URL` (a folder URL,
e.g. an internal mirror). Each file is checked against the digest pinned here and in `details.py`;
files already present and correct are kept, so a second run downloads nothing.
"""

from __future__ import annotations

import os
from pathlib import Path
import sys
import urllib.request

from .details import MODEL_FILES, _sha256, model_dir

RELEASE_URL = "https://github.com/synvo-ai/pace-connector/releases/download/detail-model-v1/"
# The model's licence and where it comes from travel with it.
NOTICE_FILES = {
    "LICENSE": "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
    "NOTICE": "2a77c09a9911f8a3982b77c0b2340f8946724be1d4ff74153a25f0350eb7b659",
}


def fetch(target: Path, base_url: str = RELEASE_URL) -> None:
    target.mkdir(parents=True, exist_ok=True)
    base_url = base_url if base_url.endswith("/") else base_url + "/"
    for name, digest in {**MODEL_FILES, **NOTICE_FILES}.items():
        destination = target / name
        if destination.exists() and _sha256(destination) == digest:
            print(f"ok    {destination}", flush=True)
            continue
        partial = destination.with_name(name + ".part")
        print(f"fetch {base_url}{name}", flush=True)
        with urllib.request.urlopen(base_url + name, timeout=60) as response, partial.open("wb") as handle:
            while block := response.read(1 << 20):
                handle.write(block)
        if _sha256(partial) != digest:
            partial.unlink()
            raise SystemExit(f"digest mismatch for {name}; nothing was kept")
        partial.replace(destination)
        print(f"ok    {destination}", flush=True)


def main(argv: list[str] | None = None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    target = Path(argv[0]).expanduser() if argv else model_dir()
    fetch(target, os.environ.get("PACE_DETAIL_MODEL_URL", RELEASE_URL))
    if target != model_dir():
        print(f"set PACE_DETAIL_MODEL_DIR={target} before starting the connector")


if __name__ == "__main__":
    main()
