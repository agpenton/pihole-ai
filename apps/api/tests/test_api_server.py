"""Focused behavior tests for the pihole-ai API server."""

from __future__ import annotations

from collections.abc import AsyncIterator, Generator
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pihole_common.models import ApprovalAudit, BlockRecommendation, DomainAssessment

from pihole_api_server import create_app
from pihole_api_server.dependencies import get_db_session, get_pihole_client
from pihole_api_server.pihole_client import BlockDomainResult, PiholeClientError


class FakeResult:
    """Small async SQLAlchemy result stand-in for route-level tests."""

    def __init__(self, rows: list[tuple[DomainAssessment, str]] | None = None) -> None:
        self._rows = rows or []

    def all(self) -> list[tuple[DomainAssessment, str]]:
        """Return selected assessment rows."""
        return self._rows


class FakeSession:
    """Database stand-in covering the read operations used by these tests."""

    def __init__(
        self,
        rows: list[tuple[DomainAssessment, str]] | None = None,
        scalar_values: list[Any] | None = None,
    ) -> None:
        self.rows = rows or []
        self.scalar_values = list(scalar_values or [])
        self.added: list[Any] = []
        self.commits = 0

    async def execute(self, _statement: Any) -> FakeResult:
        """Return the configured assessment rows."""
        return FakeResult(self.rows)

    async def scalar(self, _statement: Any) -> Any:
        """Return configured values, then the assessment row count."""
        if self.scalar_values:
            return self.scalar_values.pop(0)
        return len(self.rows)

    def add(self, value: Any) -> None:
        """Record an ORM object scheduled for insertion."""
        if isinstance(value, ApprovalAudit) and value.id is None:
            value.id = len(self.added) + 1
        self.added.append(value)

    async def commit(self) -> None:
        """Record a transaction commit."""
        self.commits += 1

    async def refresh(self, _value: Any) -> None:
        """Keep fake ORM objects available after a commit."""


class FakePiholeClient:
    """Mock Pi-hole client for block-application route tests."""

    def __init__(
        self, result: BlockDomainResult | None = None, error: Exception | None = None
    ) -> None:
        self.result = result or BlockDomainResult()
        self.error = error
        self.calls: list[tuple[str, str | None]] = []

    async def add_block_domain(
        self, domain: str, comment: str | None = None
    ) -> BlockDomainResult:
        """Return a configured result and record the mutation request."""
        self.calls.append((domain, comment))
        if self.error is not None:
            raise self.error
        return self.result


@pytest.fixture
def api_app() -> Generator[FastAPI, None, None]:
    """Create an app with its database dependency replaced by a fake session."""
    now = datetime.now(UTC)
    assessment = DomainAssessment(
        id=1,
        domain_id=1,
        suspicion_score=0.8,
        threat_categories=["threat:malware"],
        evidence={"source": "test"},
        status="pending",
        created_at=now,
        updated_at=now,
    )
    session = FakeSession([(assessment, "example.com")])

    async def override_db() -> AsyncIterator[FakeSession]:
        yield session

    app = create_app()
    app.dependency_overrides[get_db_session] = override_db
    yield app
    app.dependency_overrides.clear()


def test_health_reports_database_connection(api_app: FastAPI) -> None:
    """The health endpoint reports an available database and API version."""
    response = TestClient(api_app).get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "version": "0.1.0",
        "db_connected": True,
    }
    assert response.headers["X-Request-ID"]


def test_assessments_are_paginated(api_app: FastAPI) -> None:
    """Assessment listing preserves pagination and response fields."""
    response = TestClient(api_app).get("/assessments?page=1&page_size=1")

    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["pages"] == 1
    assert response.json()["items"][0]["domain"] == "example.com"
    assert response.json()["items"][0]["threat_categories"] == ["threat:malware"]


def test_invalid_approval_request_is_rejected(api_app: FastAPI) -> None:
    """Approval routes reject a body whose action targets another operation."""
    response = TestClient(api_app).post(
        "/assessments/1/approve", json={"action": "reject"}
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Request action must be 'approve'"


def test_invalid_approval_action_fails_schema_validation(api_app: FastAPI) -> None:
    """Approval requests only accept the documented action literals."""
    response = TestClient(api_app).post(
        "/assessments/1/reject", json={"action": "delete"}
    )

    assert response.status_code == 422


def test_api_key_protects_assessment_listing(
    api_app: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Configured API keys protect routes while preserving successful access."""
    monkeypatch.setenv("PIHOLE_API_KEY", "test-key")
    client = TestClient(api_app)

    assert client.get("/assessments").status_code == 401
    response = client.get("/assessments", headers={"X-API-Key": "test-key"})

    assert response.status_code == 200
    assert response.json()["total"] == 1


def test_metrics_endpoint_returns_prometheus_payload(api_app: FastAPI) -> None:
    """Metrics remain available as a Prometheus-compatible response."""
    response = TestClient(api_app).get("/metrics")

    assert response.status_code == 200
    assert "pihole_api_requests_total" in response.text
    assert response.headers["content-type"].startswith("text/plain")


def _application_app(
    assessment_status: str = "approved",
    client: FakePiholeClient | None = None,
) -> tuple[FastAPI, FakeSession, FakePiholeClient]:
    """Build an application with an approved recommendation and mocked Pi-hole."""
    now = datetime.now(UTC)
    recommendation = BlockRecommendation(
        id=7,
        domain="example.com",
        reason="test recommendation",
        suspicion_score=0.9,
        approved_by="operator",
        approved_at=now,
        created_at=now,
    )
    assessment = DomainAssessment(
        id=3,
        domain_id=1,
        suspicion_score=0.9,
        status=assessment_status,
        created_at=now,
        updated_at=now,
    )
    session = FakeSession(scalar_values=[recommendation, assessment])
    pihole_client = client or FakePiholeClient()

    async def override_db() -> AsyncIterator[FakeSession]:
        yield session

    app = create_app()
    app.dependency_overrides[get_db_session] = override_db
    app.dependency_overrides[get_pihole_client] = lambda: pihole_client
    return app, session, pihole_client


def test_apply_approval_mutates_pihole_and_records_audit() -> None:
    """A successful Pi-hole mutation marks the assessment blocked and audits it."""
    app, session, client = _application_app()

    response = TestClient(app).post(
        "/approvals/EXAMPLE.com/apply", headers={"X-User": "alice"}
    )

    assert response.status_code == 200
    assert response.json()["status"] == "blocked"
    assert response.json()["already_present"] is False
    assert client.calls == [("example.com", "test recommendation")]
    assert session.scalar_values == []
    assert session.added[-1].action == "apply"
    assert session.added[-1].actor == "alice"
    assert session.commits == 1
    assert response.json()["audit_id"] == session.added[-1].id
    app.dependency_overrides.clear()


def test_apply_approval_is_idempotent_when_already_blocked() -> None:
    """A retry after success does not issue a second Pi-hole mutation."""
    app, session, client = _application_app(assessment_status="blocked")

    response = TestClient(app).post("/approvals/example.com/apply")

    assert response.status_code == 200
    assert response.json()["already_present"] is True
    assert client.calls == []
    assert session.added[-1].action == "apply"
    app.dependency_overrides.clear()


def test_apply_approval_records_failure_and_returns_bad_gateway() -> None:
    """A Pi-hole failure persists failed status and an apply-failed audit."""
    client = FakePiholeClient(error=PiholeClientError("connection refused"))
    app, session, _ = _application_app(client=client)

    response = TestClient(app).post("/approvals/example.com/apply")

    assert response.status_code == 502
    assert response.json()["detail"] == "Failed to apply block to Pi-hole"
    assert session.scalar_values == []
    assert session.added[-1].action == "apply_failed"
    assert session.added[-1].reason == "connection refused"
    app.dependency_overrides.clear()
