"""fetch_model: downloads the detail model from a folder URL and keeps only files whose digest matches."""

import functools
import hashlib
import http.server
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from pace_connector import fetch_model


class FetchModelTests(unittest.TestCase):
    def setUp(self):
        self.source = tempfile.TemporaryDirectory()
        self.target = tempfile.TemporaryDirectory()
        self.files = {"a.bin": b"weights" * 1000, "LICENSE": b"licence text"}
        for name, data in self.files.items():
            (Path(self.source.name) / name).write_bytes(data)
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=self.source.name)
        handler.log_message = lambda *args: None
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.source.cleanup()
        self.target.cleanup()

    def pinned(self, **override):
        digests = {name: hashlib.sha256(data).hexdigest() for name, data in self.files.items()}
        digests.update(override)
        return mock.patch.multiple(fetch_model, MODEL_FILES={"a.bin": digests["a.bin"]}, NOTICE_FILES={"LICENSE": digests["LICENSE"]})

    def test_downloads_and_checks_each_file(self):
        with self.pinned():
            fetch_model.fetch(Path(self.target.name), self.url)
        for name, data in self.files.items():
            self.assertEqual((Path(self.target.name) / name).read_bytes(), data)

    def test_a_changed_file_is_not_kept(self):
        with self.pinned(**{"a.bin": "0" * 64}), self.assertRaises(SystemExit):
            fetch_model.fetch(Path(self.target.name), self.url)
        self.assertEqual(list(Path(self.target.name).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
