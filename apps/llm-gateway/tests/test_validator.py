"""Focused tests for OpenRouter response validation."""

from __future__ import annotations

import pytest  # type: ignore[import-not-found]

from pihole_llm_gateway.validator import ResponseValidator


def test_validate_plain_json_and_normalizes_values() -> None:
    """Valid JSON is returned with trimmed reasons and rounded confidence."""
    validator = ResponseValidator()
    result = validator.validate(
        '{"is_malicious": true, "reason": "  known phishing domain  ", "confidence": 0.876543}'
    )

    assert result == {
        "is_malicious": True,
        "reason": "known phishing domain",
        "confidence": 0.8765,
    }


def test_validate_json_markdown_code_block() -> None:
    """JSON wrapped in a fenced markdown block is accepted."""
    validator = ResponseValidator()
    result = validator.validate(
        'The assessment is below.\n```json\n{"is_malicious": false, "reason": "No indicators", "confidence": 0.12}\n```'
    )

    assert result["is_malicious"] is False
    assert result["reason"] == "No indicators"
    assert result["confidence"] == 0.12


def test_validate_rejects_malformed_or_incomplete_responses() -> None:
    """Malformed JSON, non-objects, and missing fields are rejected clearly."""
    validator = ResponseValidator()
    cases = [
        ("not json", "Response is not valid JSON"),
        ("[]", "Expected JSON object"),
        ('{"is_malicious": false, "confidence": 0.2}', "Missing required fields"),
    ]

    for response, message in cases:
        with pytest.raises((TypeError, ValueError), match=message):
            validator.validate(response)


def test_validate_rejects_invalid_field_types_and_ranges() -> None:
    """Each required field enforces its documented type and confidence range."""
    validator = ResponseValidator()
    cases: list[tuple[str, str, type[Exception]]] = [
        ("is_malicious", '"yes"', TypeError),
        ("reason", "42", TypeError),
        ("reason", '"   "', TypeError),
        ("confidence", '"high"', TypeError),
        ("confidence", "-0.01", ValueError),
        ("confidence", "1.01", ValueError),
    ]

    for field, value, exception in cases:
        values = {
            "is_malicious": "false",
            "reason": '"safe"',
            "confidence": "0.5",
        }
        values[field] = value

        with pytest.raises(exception):
            validator.validate(
                "{"
                + ", ".join(f'"{key}": {item}' for key, item in values.items())
                + "}"
            )


def test_validate_preserves_extra_fields_without_returning_them() -> None:
    """Unknown model fields do not leak into the validated result."""
    validator = ResponseValidator()
    result = validator.validate(
        '{"is_malicious": false, "reason": "safe", "confidence": 0.5, "extra": "ignored"}'
    )

    assert result == {"is_malicious": False, "reason": "safe", "confidence": 0.5}
