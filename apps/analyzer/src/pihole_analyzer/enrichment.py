"""Enrichment service — combines threat matches with deterministic rules to produce a suspicion score."""

from __future__ import annotations

import logging
import re
from typing import Any

from pihole_common.config import get_settings
from pihole_common.security import extract_tld

logger = logging.getLogger(__name__)


class EnrichmentService:
    """Calculate suspicion scores and enrich assessment payloads."""

    # Confidence tiers used by the enrichment algorithm
    _HIGH_CONFIDENCE_THRESHOLD = 0.8
    _MEDIUM_CONFIDENCE_THRESHOLD = 0.5

    # Score contributions per match
    _HIGH_CONFIDENCE_SCORE = 0.4
    _MEDIUM_CONFIDENCE_SCORE = 0.2
    _LOW_CONFIDENCE_SCORE = 0.1

    # Maximum cap
    _MAX_SCORE = 1.0

    def __init__(self) -> None:
        self._settings = get_settings()
        self._compiled_patterns: list[tuple[str, re.Pattern[str]]] = [
            (pat, re.compile(pat)) for pat in self._settings.analyzer.blocklist_patterns
        ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enrich_assessment(
        self,
        domain: str,
        threat_matches: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Enrich a domain with a suspicion score and supporting evidence.

        Args:
            domain: A normalized domain name.
            threat_matches: Results from ``ThreatChecker.check_domain``.

        Returns:
            Dict with keys: suspicion_score, threat_categories, evidence,
            matches_deterministic, needs_llm.
        """
        categories: list[str] = []
        score = 0.0
        evidence: dict[str, Any] = {}

        # --- Threat intelligence matches ---
        if threat_matches:
            for match in threat_matches:
                confidence = match.get("confidence", 0.0)
                category = match.get("category", "unknown")
                source = match.get("source", "unknown")

                if confidence >= self._HIGH_CONFIDENCE_THRESHOLD:
                    score += self._HIGH_CONFIDENCE_SCORE
                    categories.append(f"threat:{category}")
                elif confidence >= self._MEDIUM_CONFIDENCE_THRESHOLD:
                    score += self._MEDIUM_CONFIDENCE_SCORE
                    categories.append(f"threat:{category}")
                else:
                    score += self._LOW_CONFIDENCE_SCORE
                    categories.append(f"threat:{category}")

                evidence.setdefault("threat_matches", []).append(
                    {"category": category, "confidence": confidence, "source": source}
                )

        # --- Deterministic TLD weight ---
        tld = extract_tld(domain)
        tld_weights = self._settings.analyzer.suspicious_tld_weights
        if tld and tld in tld_weights:
            weight = tld_weights[tld]
            score += weight * 0.1
            categories.append(f"suspicious_tld:{tld}")
            evidence["tld_weight"] = {"tld": tld, "weight": weight}

        # --- Regex pattern matches ---
        for label, pattern in self._compiled_patterns:
            if pattern.search(domain):
                score += 0.3
                categories.append(f"pattern_match:{label}")
                evidence.setdefault("pattern_matches", []).append({"pattern": label, "domain": domain})

        # --- Short domain heuristic ---
        if len(domain.split(".")[0]) < 5:
            score += 0.2
            categories.append("short_domain")
            evidence["short_domain"] = True

        # --- Cap and normalise ---
        score = min(score, self._MAX_SCORE)
        score = round(score, 4)

        # Deduplicate categories while preserving order
        seen: set[str] = set()
        unique_categories: list[str] = []
        for cat in categories:
            if cat not in seen:
                seen.add(cat)
                unique_categories.append(cat)

        needs_llm = score >= self._settings.analyzer.min_suspicion_score

        return {
            "suspicion_score": score,
            "threat_categories": unique_categories,
            "evidence": evidence,
            "needs_llm": needs_llm,
        }
