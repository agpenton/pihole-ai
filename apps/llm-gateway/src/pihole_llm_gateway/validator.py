"""Response validation for LLM-assessed domains."""

from __future__ import annotations

import json
import logging
import re

logger = logging.getLogger(__name__)


class ResponseValidator:
    """Validates and parses JSON responses from the LLM."""

    REQUIRED_FIELDS = frozenset({"is_malicious", "reason", "confidence"})

    def validate(self, response: str) -> dict[str, object]:
        """Validate an LLM response string.

        Attempts to parse JSON from the response, handling cases where the
        model wraps JSON in markdown code blocks or adds explanatory text.

        Args:
            response: Raw text response from the LLM.

        Returns:
            Validated dict with is_malicious (bool), reason (str), confidence (float).

        Raises:
            ValueError: If the response cannot be parsed or validated.
        """
        text = response.strip()

        # Try to extract JSON from markdown code blocks
        json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if json_match:
            text = json_match.group(1)

        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Response is not valid JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise TypeError(f"Expected JSON object, got {type(data).__name__}")

        # Check required fields
        missing = self.REQUIRED_FIELDS - set(data.keys())
        if missing:
            raise ValueError(f"Missing required fields: {missing}")

        # Validate types and ranges
        is_malicious = data["is_malicious"]
        if not isinstance(is_malicious, bool):
            raise TypeError(
                f"is_malicious must be bool, got {type(is_malicious).__name__}"
            )

        reason = data["reason"]
        if not isinstance(reason, str) or not reason.strip():
            raise TypeError(
                f"reason must be a non-empty string, got {type(reason).__name__}"
            )

        confidence = data["confidence"]
        if not isinstance(confidence, (int, float)):
            raise TypeError(
                f"confidence must be a number, got {type(confidence).__name__}"
            )
        confidence = float(confidence)
        if not (0.0 <= confidence <= 1.0):
            raise ValueError(f"confidence must be between 0 and 1, got {confidence}")

        validated = {
            "is_malicious": is_malicious,
            "reason": reason.strip(),
            "confidence": round(confidence, 4),
        }

        logger.info(
            "response_validated",
            extra={"is_malicious": is_malicious, "confidence": confidence},
        )
        return validated
