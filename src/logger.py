"""
Structured JSON Logging with Audit Trail

Features:
- JSON-formatted logs for machine parsing
- PII/payload scrubbing
- HMAC chain for tamper-evident audit records
- Trace ID propagation
"""

import hashlib
import hmac
import json
import logging
import sys
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

import structlog

# Trace ID context for request correlation
trace_id_var: ContextVar[str] = ContextVar("trace_id", default="")


def get_trace_id() -> str:
    """Get current trace ID or generate new one."""
    if not (tid := trace_id_var.get()):
        tid = str(uuid.uuid4())[:8]
        trace_id_var.set(tid)
    return tid


def set_trace_id(trace_id: str) -> None:
    """Set trace ID for current context."""
    trace_id_var.set(trace_id)


# PII patterns to scrub
PII_PATTERNS = {
    "password", "secret", "token", "key", "credential",
    "ssn", "credit_card", "email", "phone"
}


def scrub_sensitive(data: dict[str, Any], scrub_pii: bool = True) -> dict[str, Any]:
    """Recursively scrub sensitive fields from log data."""
    if not scrub_pii:
        return data
    
    result: dict[str, Any] = {}
    for k, v in data.items():
        key_lower = k.lower()
        if any(pattern in key_lower for pattern in PII_PATTERNS):
            result[k] = "[REDACTED]"
        elif isinstance(v, dict):
            result[k] = scrub_sensitive(v, scrub_pii)
        else:
            result[k] = v
    return result


def add_trace_id(logger: Any, method_name: str, event_dict: dict) -> dict:
    """Add trace ID to log records."""
    event_dict["trace_id"] = get_trace_id()
    return event_dict


def add_timestamp(logger: Any, method_name: str, event_dict: dict) -> dict:
    """Add ISO timestamp to log records."""
    event_dict["timestamp"] = datetime.now(timezone.utc).isoformat()
    return event_dict


def configure_logging(
    level: str = "INFO",
    json_format: bool = True,
    scrub_pii: bool = True
) -> None:
    """Configure structured logging for the application."""
    
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        add_timestamp,
        add_trace_id,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    
    if json_format:
        processors.append(structlog.processors.JSONRenderer(
            serializer=lambda obj, **kw: json.dumps(
                scrub_sensitive(obj, scrub_pii) if isinstance(obj, dict) else obj,
                sort_keys=True,
                separators=(",", ":")
            )
        ))
    else:
        processors.append(structlog.dev.ConsoleRenderer())
    
    structlog.configure(
        processors=processors,  # type: ignore[arg-type]
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper())
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    # Configure stdlib logging to use structlog
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level.upper()),
    )


def get_logger(name: str) -> structlog.BoundLogger:
    """Get a structured logger for the given module."""
    return structlog.get_logger(name)


class AuditLogger:
    """
    Tamper-evident audit logging with HMAC chain.
    
    Each audit record includes an HMAC computed over:
    - Previous record's HMAC (or empty string for first)
    - Canonicalized JSON payload
    
    The HMAC key is stored in Vault and rotated according to policy.
    """
    
    def __init__(self, hmac_key: bytes):
        self._hmac_key = hmac_key
        self._prev_hmac: str | None = None
        self._logger = get_logger("audit")
    
    def compute_hmac(self, payload: dict[str, Any]) -> str:
        """
        Compute HMAC for audit record.
        
        Uses HMAC-SHA256 over: prev_hmac || canonicalized_json(payload)
        """
        # Canonicalized JSON: sorted keys, minimal separators
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        data = (self._prev_hmac or "").encode() + canonical.encode()
        return hmac.new(self._hmac_key, data, hashlib.sha256).hexdigest()
    
    def log(
        self,
        action: str,
        user_id: str,
        target: str | None = None,
        scope_ticket: str | None = None,
        result: dict[str, Any] | None = None,
        **extra: Any
    ) -> dict[str, Any]:
        """
        Create tamper-evident audit record.
        
        Returns the full record including HMAC for database storage.
        """
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "user_id": user_id,
            "target": target,
            "scope_ticket": scope_ticket,
            "result": result or {},
            "trace_id": get_trace_id(),
            **extra
        }
        
        record_hmac = self.compute_hmac(payload)
        
        full_record = {
            **payload,
            "prev_hmac": self._prev_hmac,
            "hmac": record_hmac
        }
        
        # Update chain
        self._prev_hmac = record_hmac
        
        # Log (structured)
        self._logger.info(
            "audit_record",
            action=action,
            user_id=user_id,
            target=target,
            hmac=record_hmac[:16] + "..."  # Truncated for log
        )
        
        return full_record
    
    @staticmethod
    def verify_chain(records: list[dict[str, Any]], hmac_key: bytes) -> bool:
        """
        Verify integrity of audit chain.
        
        Returns True if all records are valid and chain is unbroken.
        """
        prev_hmac: str | None = None
        
        for record in records:
            # Reconstruct payload (exclude hmac fields)
            payload = {k: v for k, v in record.items() if k not in ("hmac", "prev_hmac")}
            
            # Verify prev_hmac matches
            if record.get("prev_hmac") != prev_hmac:
                return False
            
            # Verify HMAC
            canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            data = (prev_hmac or "").encode() + canonical.encode()
            expected = hmac.new(hmac_key, data, hashlib.sha256).hexdigest()
            
            if record.get("hmac") != expected:
                return False
            
            prev_hmac = record["hmac"]
        
        return True
