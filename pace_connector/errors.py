"""Typed, payload-free failures exposed by the connector."""


class ConnectorError(Exception):
    code = "INTERNAL_CONNECTOR_ERROR"
    safe_message = "The email could not be prepared safely."

    def __str__(self) -> str:
        return self.safe_message


class MalformedEmailError(ConnectorError):
    code = "MALFORMED_EMAIL"
    safe_message = "The email is malformed or has no usable message body."


class BodyUnavailableError(ConnectorError):
    code = "BODY_UNAVAILABLE"
    safe_message = "The email body could not be decoded within the connector policy."


class RequestLimitError(ConnectorError):
    code = "REQUEST_LIMIT_EXCEEDED"
    safe_message = "The email exceeds a configured local connector limit."


class AttachmentLimitError(ConnectorError):
    code = "ATTACHMENT_LIMIT_EXCEEDED"
    safe_message = "The email has too many attachments or excessive attachment metadata."


class MaskingFailureError(ConnectorError):
    code = "MASKING_FAILURE"
    safe_message = "The email could not be masked safely."


class PrivacyDetectorFailureError(ConnectorError):
    code = "PRIVACY_DETECTOR_FAILURE"
    safe_message = "Local privacy detection could not complete safely."


class PrivacyScopeUnsupportedError(ConnectorError):
    code = "PRIVACY_SCOPE_UNSUPPORTED"
    safe_message = "The content is outside the configured local privacy scope."


class EgressPrivacyCheckFailedError(ConnectorError):
    code = "EGRESS_PRIVACY_CHECK_FAILED"
    safe_message = "The message could not pass the local outbound privacy check."


class EngineUnavailableError(ConnectorError):
    code = "ENGINE_UNAVAILABLE"
    safe_message = "The local intelligence endpoint is unavailable."


class EngineContractRejectedError(ConnectorError):
    code = "ENGINE_CONTRACT_REJECTED"
    safe_message = "The local intelligence endpoint rejected the canonical request or response."


class AuthenticationFailureError(ConnectorError):
    code = "AUTHENTICATION_FAILURE"
    safe_message = "The local intelligence endpoint did not accept the connector authentication."


class IdempotencyConflictError(ConnectorError):
    code = "IDEMPOTENCY_CONFLICT"
    safe_message = "The idempotency key was already used for a different request."


class RateLimitedError(ConnectorError):
    code = "RATE_LIMITED"
    safe_message = "The local intelligence endpoint is temporarily rate limited."

    def __init__(self, retry_after_seconds: float) -> None:
        self.retry_after_seconds = retry_after_seconds


class DeliveryConfigurationError(ConnectorError):
    code = "DELIVERY_CONFIGURATION"
    safe_message = "The local intelligence delivery runtime is not safely configured."
