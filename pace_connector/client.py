"""A narrow standard-library HTTP client. It neither logs nor persists payloads."""

from __future__ import annotations

import json
from dataclasses import dataclass
import time
from typing import Any, Callable, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .contracts import HTTP_CONTRACT_VERSION
from .errors import (
    AuthenticationFailureError,
    DeliveryConfigurationError,
    EngineContractRejectedError,
    EngineUnavailableError,
    IdempotencyConflictError,
    RateLimitedError,
)


class EngineClient(Protocol):
    def analyse(self, canonical_request: dict[str, Any]) -> dict[str, Any]: ...


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    base_delay_seconds: float = 0.05
    max_delay_seconds: float = 1.0
    sleeper: Callable[[float], None] = time.sleep


@dataclass(frozen=True)
class LocalHttpEngineClient:
    endpoint: str
    api_key: str
    timeout_seconds: float = 5.0
    retry_policy: RetryPolicy = RetryPolicy()

    def analyse(self, canonical_request: dict[str, Any]) -> dict[str, Any]:
        payload = json.dumps(canonical_request, separators=(",", ":")).encode("utf-8")
        request = Request(
            f"{self.endpoint.rstrip('/')}/v0/enquiries?mode=sync",
            data=payload,
            headers={"content-type": "application/json", "x-api-key": self.api_key},
            method="POST",
        )
        has_idempotency = _valid_idempotency_key(canonical_request.get("idempotencyKey"))
        attempts = max(1, self.retry_policy.max_attempts)
        for attempt in range(attempts):
            try:
                return self._send(request)
            except (EngineUnavailableError, RateLimitedError) as error:
                if not has_idempotency or attempt + 1 >= attempts:
                    raise
                delay = error.retry_after_seconds if isinstance(error, RateLimitedError) else self.retry_policy.base_delay_seconds * (2 ** attempt)
                self.retry_policy.sleeper(min(max(0.0, delay), self.retry_policy.max_delay_seconds))
        raise EngineUnavailableError()

    def _send(self, request: Request) -> dict[str, Any]:
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                if response.status != 200:
                    raise EngineContractRejectedError()
                body = response.read()
        except HTTPError as error:
            raise _map_http_error(error) from error
        except (URLError, TimeoutError, OSError) as error:
            raise EngineUnavailableError() from error
        return _parse_success(body)


def _parse_success(body: bytes) -> dict[str, Any]:
    try:
        decoded = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EngineContractRejectedError() from error
    if not isinstance(decoded, dict) or decoded.get("schemaVersion") != HTTP_CONTRACT_VERSION or not isinstance(decoded.get("result"), dict):
        raise EngineContractRejectedError()
    return decoded


def _map_http_error(error: HTTPError) -> Exception:
    try:
        try:
            body = error.read()
        finally:
            error.close()
        decoded = json.loads(body.decode("utf-8"))
        code = decoded.get("error", {}).get("code") if isinstance(decoded, dict) and isinstance(decoded.get("error"), dict) else None
    except (UnicodeDecodeError, json.JSONDecodeError, OSError):
        return EngineContractRejectedError()
    if error.code == 401 and code == "AUTHENTICATION_REQUIRED":
        return AuthenticationFailureError()
    if error.code == 409 and code == "IDEMPOTENCY_CONFLICT":
        return IdempotencyConflictError()
    if error.code == 429 and code in {"RATE_LIMITED", "CONCURRENCY_LIMITED"}:
        return RateLimitedError(_retry_after(error.headers.get("Retry-After")))
    if error.code == 500 and code == "DELIVERY_CONFIGURATION":
        return DeliveryConfigurationError()
    if error.code >= 500 and code in {"ENGINE_FAILURE", "IDEMPOTENCY_STORE_UNAVAILABLE", "IDEMPOTENCY_IN_FLIGHT_TIMEOUT"}:
        return EngineUnavailableError()
    if error.code in {400, 413, 422} and code in {"INVALID_REQUEST", "UNSUPPORTED_SCHEMA_VERSION", "PAYLOAD_TOO_LARGE", "UNSUPPORTED_MODE", "INPUT_CLASS_NOT_ACCEPTED"}:
        return EngineContractRejectedError()
    return EngineContractRejectedError()


def _retry_after(value: str | None) -> float:
    try:
        return max(0.0, float(value)) if value is not None else 0.0
    except ValueError:
        return 0.0


def _valid_idempotency_key(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 160 and not any(ord(character) < 32 or ord(character) == 127 for character in value)
