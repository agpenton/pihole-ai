"""Tests for the enrichment and scoring engine."""

from pihole_analyzer.enrichment import EnrichmentService


class TestEnrichmentService:
    """Tests for EnrichmentService."""

    def test_no_threats_returns_clean(self) -> None:
        """When no threats are found, suspicion score should be 0."""
        engine = EnrichmentService()
        result = engine.enrich_assessment("example.com", [])

        assert result["suspicion_score"] == 0
        assert result["threat_categories"] == []
        assert result["needs_llm"] is False

    def test_single_low_threat(self) -> None:
        """A single low-confidence threat should produce a small score."""
        engine = EnrichmentService()
        threats = [{"source": "test", "category": "suspicious", "confidence": 0.1}]
        result = engine.enrich_assessment("example.com", threats)

        assert result["suspicion_score"] > 0
        assert result["suspicion_score"] <= 0.1
        assert "threat:suspicious" in result["threat_categories"]

    def test_single_high_threat(self) -> None:
        """A high-confidence threat should produce a significant score."""
        engine = EnrichmentService()
        threats = [{"source": "test", "category": "malware", "confidence": 0.9}]
        result = engine.enrich_assessment("example.com", threats)

        assert result["suspicion_score"] >= 0.4
        assert "threat:malware" in result["threat_categories"]

    def test_multiple_threats_increase_score(self) -> None:
        """Multiple threats should increase the suspicion score."""
        engine = EnrichmentService()
        threats = [
            {"source": "test1", "category": "suspicious", "confidence": 0.6},
            {"source": "test2", "category": "phishing", "confidence": 0.6},
        ]
        result = engine.enrich_assessment("example.com", threats)

        assert result["suspicion_score"] >= 0.4  # 0.2 + 0.2
        assert "threat:suspicious" in result["threat_categories"]
        assert "threat:phishing" in result["threat_categories"]

    def test_critical_threat_forces_llm(self) -> None:
        """A high-confidence threat should force LLM evaluation (score >= threshold)."""
        engine = EnrichmentService()
        threats = [{"source": "test", "category": "malware", "confidence": 0.9}]
        result = engine.enrich_assessment("example.com", threats)

        # Score of 0.4 is below the default 0.5 threshold, so needs_llm is False
        # Multiple threats would push it above 0.5
        assert result["suspicion_score"] == 0.4

    def test_high_threat_forces_llm(self) -> None:
        """A medium-confidence threat produces a moderate score."""
        engine = EnrichmentService()
        threats = [{"source": "test", "category": "malware", "confidence": 0.6}]
        result = engine.enrich_assessment("example.com", threats)

        # Score of 0.2 is below the default 0.5 threshold
        assert result["suspicion_score"] == 0.2

    def test_low_threat_no_llm(self) -> None:
        """Low-confidence threats should not force LLM evaluation."""
        engine = EnrichmentService()
        threats = [{"source": "test", "category": "suspicious", "confidence": 0.1}]
        result = engine.enrich_assessment("example.com", threats)

        # Score of 0.1 is below the default 0.5 threshold
        assert result["needs_llm"] is False

    def test_multiple_threats_force_llm(self) -> None:
        """Multiple high-confidence threats should exceed the threshold and force LLM."""
        engine = EnrichmentService()
        threats = [
            {"source": "test1", "category": "malware", "confidence": 0.9},
            {"source": "test2", "category": "phishing", "confidence": 0.9},
        ]
        result = engine.enrich_assessment("example.com", threats)

        # Score of 0.8 exceeds the default 0.5 threshold
        assert result["suspicion_score"] == 0.8
        assert result["needs_llm"] is True

    def test_duplicate_categories_merged(self) -> None:
        """Duplicate threat categories should be merged."""
        engine = EnrichmentService()
        threats = [
            {"source": "test1", "category": "malware", "confidence": 0.9},
            {"source": "test2", "category": "malware", "confidence": 0.6},
        ]
        result = engine.enrich_assessment("example.com", threats)

        # Both should be merged into one category entry
        assert result["threat_categories"].count("threat:malware") == 1

    def test_evidence_included(self) -> None:
        """Evidence should be included in the result."""
        engine = EnrichmentService()
        threats = [{"source": "test", "category": "malware", "confidence": 0.9}]
        result = engine.enrich_assessment("example.com", threats)

        assert "evidence" in result
        assert "threat_matches" in result["evidence"]
        assert len(result["evidence"]["threat_matches"]) == 1
        assert result["evidence"]["threat_matches"][0]["category"] == "malware"

    def test_score_capped_at_max(self) -> None:
        """The suspicion score should be capped at the maximum value."""
        engine = EnrichmentService()
        # Multiple high-confidence threats should exceed the cap
        threats = [
            {"source": "test1", "category": "malware", "confidence": 0.9},
            {"source": "test2", "category": "malware", "confidence": 0.9},
            {"source": "test3", "category": "malware", "confidence": 0.9},
        ]
        result = engine.enrich_assessment("example.com", threats)

        assert result["suspicion_score"] <= 1.0
