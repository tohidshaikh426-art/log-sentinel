"""Authenticated HTTPS client for Log Sentinel Supabase Edge Functions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests


@dataclass(frozen=True, slots=True)
class DeliveryResult:
    """Result of an ingestion or heartbeat HTTP request."""

    ok: bool
    retryable: bool
    status_code: int | None
    message: str
    accepted_count: int = 0
    duplicate_count: int = 0


class IngestionClient:
    """Sends batched events, incidents, and heartbeats using per-device tokens."""

    def __init__(
        self,
        *,
        ingest_url: str,
        heartbeat_url: str,
        device_id: str,
        collector_token: str,
        timeout_seconds: float = 10.0,
        session: requests.Session | None = None,
    ) -> None:
        self.ingest_url = ingest_url
        self.heartbeat_url = heartbeat_url
        self.device_id = device_id
        self.collector_token = collector_token
        self.timeout_seconds = timeout_seconds
        self._session = session or requests.Session()

    def _headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "x-device-id": self.device_id,
            "x-collector-token": self.collector_token,
        }

    def send_batch(self, payload: dict[str, Any]) -> DeliveryResult:
        """Deliver one event/incident batch to ingest-events."""
        try:
            resp = self._session.post(
                self.ingest_url,
                json=payload,
                headers=self._headers(),
                timeout=self.timeout_seconds,
            )
        except requests.RequestException as exc:
            return DeliveryResult(
                ok=False,
                retryable=True,
                status_code=None,
                message=f"Network error: {exc}",
            )

        if 200 <= resp.status_code < 300:
            data = resp.json() if resp.content else {}
            return DeliveryResult(
                ok=True,
                retryable=False,
                status_code=resp.status_code,
                message="ok",
                accepted_count=int(data.get("accepted_count", 0)),
                duplicate_count=int(data.get("duplicate_count", 0)),
            )

        retryable = resp.status_code == 429 or resp.status_code >= 500
        err_msg = f"HTTP {resp.status_code}"
        try:
            err_body = resp.json()
            if isinstance(err_body, dict) and err_body.get("error"):
                err_msg = f"HTTP {resp.status_code}: {err_body['error']}"
        except ValueError:
            pass

        return DeliveryResult(
            ok=False,
            retryable=retryable,
            status_code=resp.status_code,
            message=err_msg,
        )

    def send_heartbeat(self, *, collector_version: str, os_info: str) -> DeliveryResult:
        """Send periodic liveness heartbeat to collector-heartbeat."""
        try:
            resp = self._session.post(
                self.heartbeat_url,
                json={"collector_version": collector_version, "os_info": os_info},
                headers=self._headers(),
                timeout=self.timeout_seconds,
            )
        except requests.RequestException as exc:
            return DeliveryResult(
                ok=False,
                retryable=True,
                status_code=None,
                message=f"Heartbeat network error: {exc}",
            )

        if 200 <= resp.status_code < 300:
            return DeliveryResult(
                ok=True,
                retryable=False,
                status_code=resp.status_code,
                message="ok",
            )

        retryable = resp.status_code == 429 or resp.status_code >= 500
        return DeliveryResult(
            ok=False,
            retryable=retryable,
            status_code=resp.status_code,
            message=f"Heartbeat HTTP {resp.status_code}",
        )

    def close(self) -> None:
        self._session.close()
