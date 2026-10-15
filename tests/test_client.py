from __future__ import annotations

from email.message import Message
from io import BytesIO
import unittest
from urllib.error import HTTPError, URLError

import pace_connector.client as client_module
from pace_connector.client import LocalHttpEngineClient, RetryPolicy
from pace_connector.errors import (
    AuthenticationFailureError,
    EngineContractRejectedError,
    EngineUnavailableError,
    IdempotencyConflictError,
    RateLimitedError,
)


SUCCESS = b'{"schemaVersion":"rstn-headless-http-v0","result":{}}'
REQUEST = {"schemaVersion": "rstn-headless-http-v0", "idempotencyKey": "opaque-test-key"}


class FakeResponse:
    status = 200
    def __init__(self, body: bytes = SUCCESS) -> None: self.body = body
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self) -> bytes: return self.body


def error(status: int, code: str | None, retry_after: str | None = None) -> HTTPError:
    headers = Message()
    if retry_after is not None: headers["Retry-After"] = retry_after
    body = b"{}" if code is None else ('{"schemaVersion":"rstn-headless-http-v0","error":{"code":"' + code + '","message":"safe"}}').encode()
    return HTTPError("http://local", status, "safe", headers, BytesIO(body))


class LocalHttpEngineClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original = client_module.urlopen
        self.calls = 0

    def tearDown(self) -> None:
        client_module.urlopen = self.original

    def install(self, outcomes) -> None:
        queue = list(outcomes)
        def fake(*args, **kwargs):
            self.calls += 1
            outcome = queue.pop(0)
            if isinstance(outcome, Exception): raise outcome
            return outcome
        client_module.urlopen = fake

    def test_parses_safe_409_429_and_401_envelopes(self) -> None:
        self.install([error(409, "IDEMPOTENCY_CONFLICT")])
        with self.assertRaises(IdempotencyConflictError): LocalHttpEngineClient("http://local", "test").analyse(REQUEST)
        self.install([error(429, "RATE_LIMITED", "2")])
        with self.assertRaises(RateLimitedError) as limited: LocalHttpEngineClient("http://local", "test", retry_policy=RetryPolicy(max_attempts=1)).analyse(REQUEST)
        self.assertEqual(limited.exception.retry_after_seconds, 2)
        self.install([error(401, "AUTHENTICATION_REQUIRED")])
        with self.assertRaises(AuthenticationFailureError): LocalHttpEngineClient("http://local", "test").analyse(REQUEST)

    def test_retries_only_retryable_failures_with_an_active_idempotency_key(self) -> None:
        waits: list[float] = []
        self.install([URLError("temporary"), FakeResponse()])
        result = LocalHttpEngineClient("http://local", "test", retry_policy=RetryPolicy(max_attempts=2, base_delay_seconds=0.25, max_delay_seconds=0.25, sleeper=waits.append)).analyse(REQUEST)
        self.assertEqual(result["schemaVersion"], "rstn-headless-http-v0")
        self.assertEqual(self.calls, 2)
        self.assertEqual(waits, [0.25])

        self.install([error(429, "RATE_LIMITED", "0"), error(500, "ENGINE_FAILURE"), FakeResponse()])
        result = LocalHttpEngineClient("http://local", "test", retry_policy=RetryPolicy(max_attempts=3, max_delay_seconds=0, sleeper=lambda _: None)).analyse(REQUEST)
        self.assertEqual(result["schemaVersion"], "rstn-headless-http-v0")
        self.assertEqual(self.calls, 5)

    def test_does_not_retry_without_key_or_for_deterministic_contract_failure(self) -> None:
        self.install([URLError("temporary"), FakeResponse()])
        with self.assertRaises(EngineUnavailableError): LocalHttpEngineClient("http://local", "test", retry_policy=RetryPolicy(max_attempts=2, sleeper=lambda _: None)).analyse({"schemaVersion": "rstn-headless-http-v0"})
        self.assertEqual(self.calls, 1)
        self.install([error(400, "INVALID_REQUEST"), FakeResponse()])
        with self.assertRaises(EngineContractRejectedError): LocalHttpEngineClient("http://local", "test", retry_policy=RetryPolicy(max_attempts=2, sleeper=lambda _: None)).analyse(REQUEST)
        self.assertEqual(self.calls, 2)

    def test_unknown_or_malformed_remote_error_fails_closed(self) -> None:
        self.install([error(500, None)])
        with self.assertRaises(EngineContractRejectedError): LocalHttpEngineClient("http://local", "test").analyse(REQUEST)


if __name__ == "__main__":
    unittest.main()
