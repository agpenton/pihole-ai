"""Pi-hole API client used to apply approved domain blocks."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import httpx


class PiholeClientError(RuntimeError):
    """Raised when Pi-hole rejects or cannot process a block mutation."""


@dataclass(frozen=True)
class BlockDomainResult:
    """Result of applying a domain to Pi-hole's exact deny list."""

    already_present: bool = False


class PiholeClient:
    """Minimal Pi-hole v6 client for approved block mutations."""

    def __init__(
        self, base_url: str, api_token: str | None = None, timeout: float = 10.0
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.timeout = timeout

    def _api_base_url(self) -> str:
        """Return the Pi-hole v6 API root for supported configured URL shapes."""
        parsed = urlsplit(self.base_url)
        path = parsed.path.rstrip("/")
        if path.endswith("/admin/api.php"):
            path = "/api"
        elif not path.endswith("/api"):
            path = f"{path}/api" if path else "/api"
        return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))

    def _domain_list_url(self) -> str:
        """Return the exact deny-list endpoint."""
        return f"{self._api_base_url().rstrip('/')}/domains/deny/exact"

    def _headers(self) -> dict[str, str]:
        """Build authentication and content headers for Pi-hole v6."""
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.api_token:
            # Pi-hole v6 uses X-FTL-SID. Keeping the token in the query string
            # below also preserves compatibility with existing local setups.
            headers["X-FTL-SID"] = self.api_token
        return headers

    async def add_block_domain(
        self, domain: str, comment: str | None = None
    ) -> BlockDomainResult:
        """Ensure ``domain`` exists in Pi-hole's exact deny list.

        The read-before-write makes retries idempotent. Pi-hole versions that
        return a duplicate-entry error instead of the current list are handled
        as an already-present result when the response identifies a uniqueness
        conflict.
        """
        url = self._domain_list_url()
        params = {"auth": self.api_token} if self.api_token else None
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                existing_response = await client.get(
                    url, headers=self._headers(), params=params
                )
                if existing_response.status_code == 200:
                    existing = existing_response.json()
                    if self._contains_domain(existing, domain):
                        return BlockDomainResult(already_present=True)
                elif existing_response.status_code not in {404, 405}:
                    existing_response.raise_for_status()

                payload: dict[str, object] = {"domain": domain}
                if comment:
                    payload["comment"] = comment
                response = await client.post(
                    url, headers=self._headers(), params=params, json=payload
                )
                if response.status_code in {400, 409} and self._is_duplicate_response(
                    response
                ):
                    return BlockDomainResult(already_present=True)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            raise PiholeClientError(f"Pi-hole block mutation failed: {exc}") from exc
        except (TypeError, ValueError) as exc:
            raise PiholeClientError(
                f"Pi-hole returned an invalid response: {exc}"
            ) from exc

        return BlockDomainResult()

    @staticmethod
    def _contains_domain(payload: object, domain: str) -> bool:
        """Recognize domain-list response shapes returned by Pi-hole v6."""
        if isinstance(payload, list):
            return any(
                PiholeClient._domain_from_item(item) == domain for item in payload
            )
        if isinstance(payload, dict):
            for key in ("data", "domains", "items"):
                if key in payload and PiholeClient._contains_domain(
                    payload[key], domain
                ):
                    return True
            return PiholeClient._domain_from_item(payload) == domain
        return False

    @staticmethod
    def _domain_from_item(item: object) -> str | None:
        """Extract a domain from a list item without assuming one schema."""
        if isinstance(item, str):
            return item
        if isinstance(item, dict):
            value = item.get("domain")
            return value if isinstance(value, str) else None
        return None

    @staticmethod
    def _is_duplicate_response(response: httpx.Response) -> bool:
        """Identify Pi-hole's duplicate-domain error without hiding other errors."""
        try:
            payload = response.json()
        except ValueError:
            payload = None
        text = str(payload if payload is not None else response.text).lower()
        return "unique constraint" in text or "already" in text or "duplicate" in text
