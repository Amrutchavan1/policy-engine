import hashlib
import json
import logging
import re
from typing import Any

# Regex patterns for sensitive personal information
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
SSN_REGEX = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
AADHAAR_REGEX = re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b")
PHONE_REGEX = re.compile(r"(\+?\d{1,3}[\s-]?)?(\(?\d{3,5}\)?[\s-]?)?\d{3,5}[\s-]?\d{4}")

# Keys that must always be redacted regardless of value format
SENSITIVE_KEYS = {
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "token",
    "access_token",
    "refresh_token",
    "auth_token",
    "authorization",
    "ssn",
    "aadhaar",
    "aadhar",
    "pan",
    "credit_card",
    "cvv",
}

EMAIL_KEYS = {"email", "recipient", "recipient_email", "to", "from", "cc", "bcc"}
PHONE_KEYS = {"phone", "phone_number", "mobile", "contact", "telephone"}


def sha256_hash(value: str) -> str:
    """Return a SHA-256 hex digest of a string."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def mask_phone(phone_str: str) -> str:
    """Mask all digits except the last 4 digits of a phone number."""
    digits = re.sub(r"\D", "", phone_str)
    if len(digits) < 4:
        return "[REDACTED]"
    return f"***-***-{digits[-4:]}"


def sanitize_string(text: str) -> str:
    """Detect and sanitize PII inside free-form string values."""
    # Replace SSN and Aadhaar numbers with [REDACTED]
    text = SSN_REGEX.sub("[REDACTED]", text)
    text = AADHAAR_REGEX.sub("[REDACTED]", text)

    # Hash any email addresses found inside text
    text = EMAIL_REGEX.sub(lambda m: f"sha256:{sha256_hash(m.group(0).lower())}", text)

    # Mask any phone numbers found inside text
    text = PHONE_REGEX.sub(lambda m: mask_phone(m.group(0)), text)
    return text


def sanitize_data(data: Any, parent_key: str = "") -> Any:
    """
    Recursively sanitize nested dictionaries, lists, and primitive values
    according to Task B Data Masking & Redaction Rules.
    """
    key_lower = parent_key.lower()

    # Handle dictionaries (including nested JSON objects)
    if isinstance(data, dict):
        sanitized_dict = {}
        for k, v in data.items():
            k_lower = str(k).lower()

            # Rule 4 & 5: Do not log raw content_payload.data; store SHA-256 hash instead
            if key_lower == "content_payload" and k_lower == "data":
                raw_payload = json.dumps(v, sort_keys=True) if not isinstance(v, str) else v
                sanitized_dict["data"] = "[REDACTED]"
                sanitized_dict["payload_sha256"] = sha256_hash(raw_payload)
                continue

            # Rule 2 & 6: Never log passwords, API keys, tokens, SSN, or Aadhaar
            if k_lower in SENSITIVE_KEYS:
                sanitized_dict[k] = "[REDACTED]"
                continue

            # Rule 1: Hash recipient email addresses
            if k_lower in EMAIL_KEYS and isinstance(v, str):
                sanitized_dict[k] = f"sha256:{sha256_hash(v.strip().lower())}"
                continue

            # Rule 3: Mask phone numbers
            if k_lower in PHONE_KEYS and isinstance(v, str):
                sanitized_dict[k] = mask_phone(v)
                continue

            # Rule 7: Recursively sanitize nested objects
            sanitized_dict[k] = sanitize_data(v, parent_key=str(k))
        return sanitized_dict

    # Handle lists inside JSON payloads
    if isinstance(data, list):
        return [sanitize_data(item, parent_key=parent_key) for item in data]

    # Handle string values
    if isinstance(data, str):
        return sanitize_string(data)

    return data


class SanitizingFormatter(logging.Formatter):
    """Custom log formatter that sanitizes structured payloads before writing logs."""

    def format(self, record: logging.LogRecord) -> str:
        if isinstance(record.msg, (dict, list)):
            record.msg = json.dumps(sanitize_data(record.msg))
        elif isinstance(record.msg, str):
            # Check if the string is serialized JSON
            try:
                parsed = json.loads(record.msg)
                if isinstance(parsed, (dict, list)):
                    record.msg = json.dumps(sanitize_data(parsed))
                else:
                    record.msg = sanitize_string(record.msg)
            except (json.JSONDecodeError, TypeError):
                record.msg = sanitize_string(record.msg)

        if record.args:
            if isinstance(record.args, dict):
                record.args = sanitize_data(record.args)
            elif isinstance(record.args, tuple):
                record.args = tuple(sanitize_data(arg) for arg in record.args)

        return super().format(record)


def get_logger(name: str = "policy_engine") -> logging.Logger:
    """Configure and return a sanitized logger for local development."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = SanitizingFormatter(
            fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger
    