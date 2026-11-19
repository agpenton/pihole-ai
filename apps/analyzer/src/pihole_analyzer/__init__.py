"""Security Analyzer — deterministic threat assessment and LLM candidate selection."""

from pihole_analyzer.threat_feeds import (
    FeedRefreshResult,
    ThreatFeedAdapter,
    ThreatFeedConfig,
    ThreatFeedError,
    ThreatFeedRefresher,
    ThreatIndicator,
    load_feed_configs,
    normalize_feed_entry,
    refresh_threat_intelligence,
    upsert_threat_indicators,
)

__version__ = "0.1.0"

__all__ = [
    "FeedRefreshResult",
    "ThreatFeedAdapter",
    "ThreatFeedConfig",
    "ThreatFeedError",
    "ThreatFeedRefresher",
    "ThreatIndicator",
    "load_feed_configs",
    "normalize_feed_entry",
    "refresh_threat_intelligence",
    "upsert_threat_indicators",
]
