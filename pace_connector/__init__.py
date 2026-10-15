"""PaCE privacy connector: masks personal details in an email locally before it is sent to the engine.

It deliberately has no mailbox access and never sends email."""

from .contracts import ConnectorInput, ConnectorLimits, ConnectorResult, PriorIssue, ThreadMessage
from .service import MimePrivacyConnector

__all__ = [
    "ConnectorInput",
    "ConnectorLimits",
    "ConnectorResult",
    "MimePrivacyConnector",
    "PriorIssue",
    "ThreadMessage",
]
