"""Security utilities for domain analysis and threat scoring."""

from __future__ import annotations

import hashlib
import re

# Pre-compiled patterns for performance
_DOMAIN_PATTERN = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$",
    re.IGNORECASE,
)
_IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def normalize_domain(domain: str) -> str:
    """Normalize a domain name to lowercase, strip trailing dot, and validate.

    Args:
        domain: Raw domain string from Pi-hole.

    Returns:
        Normalized lowercase domain.

    Raises:
        ValueError: If the domain is invalid.
    """
    domain = domain.strip().lower().rstrip(".")
    if not domain:
        raise ValueError("Empty domain")
    if not _DOMAIN_PATTERN.match(domain):
        raise ValueError(f"Invalid domain: {domain}")
    return domain


def compute_evidence_hash(*parts: str) -> str:
    """Compute a SHA-256 hash from multiple evidence parts.

    Used to create unique identifiers for DNS events and assessments.

    Args:
        *parts: Variable number of evidence strings to hash.

    Returns:
        Hex-encoded SHA-256 digest (first 64 chars).
    """
    combined = "|".join(str(p) for p in parts)
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


def extract_tld(domain: str) -> str:
    """Extract the TLD from a domain name.

    Args:
        domain: A normalized domain name.

    Returns:
        The TLD including the dot (e.g., '.xyz').
    """
    parts = domain.rsplit(".", 1)
    if len(parts) == 2:
        return f".{parts[1]}"
    return ""


def compute_suspicion_score(
    domain: str,
    tld_weights: dict[str, float] | None = None,
    blocklist_patterns: list[str] | None = None,
) -> tuple[float, list[str]]:
    """Compute a deterministic suspicion score for a domain.

    Scoring rules:
    - Base score: 0.0
    - TLD weight adds to score (weighted by frequency in domain history)
    - Regex pattern match adds 0.3 per matching pattern
    - IP addresses score 0.8
    - Very short domains (< 5 chars) score 0.2

    Args:
        domain: A normalized domain name.
        tld_weights: TLD-based suspiciousness weights.
        blocklist_patterns: Regex patterns for suspicious domains.

    Returns:
        Tuple of (score, list of matched categories).
    """
    if tld_weights is None:
        tld_weights = {}
    if blocklist_patterns is None:
        blocklist_patterns = []

    score = 0.0
    categories: list[str] = []

    # IP address check
    if _IP_PATTERN.match(domain):
        score += 0.8
        categories.append("ip_address")

    # TLD weight
    tld = extract_tld(domain)
    if tld and tld in tld_weights:
        score += tld_weights[tld] * 0.1
        categories.append(f"suspicious_tld:{tld}")

    # Blocklist pattern matches
    for pattern in blocklist_patterns:
        if re.search(pattern, domain):
            score += 0.3
            categories.append(f"pattern_match:{pattern}")

    # Short domain heuristic
    if len(domain.split(".")[0]) < 5:
        score += 0.2
        categories.append("short_domain")

    return round(score, 4), categories


def validate_domain_chain(chain: list[str] | None) -> list[str] | None:
    """Validate and normalize a DNS query chain.

    Args:
        chain: List of domains from Pi-hole query chain.

    Returns:
        Normalized chain or None if input was None.
    """
    if chain is None:
        return None
    normalized: list[str] = []
    for domain in chain:
        try:
            normalized.append(normalize_domain(domain))
        except ValueError:
            continue
    return normalized if normalized else None
