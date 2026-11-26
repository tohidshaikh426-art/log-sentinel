"""Configuration loader and validator for the Log Sentinel Python collector."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from urllib.parse import urlparse
import uuid

from dotenv import load_dotenv


class ConfigError(ValueError):
    """Raised when collector configuration is missing or invalid."""


def _validate_endpoint_url(url: str, label: str) -> str:
    cleaned = url.strip()
    if not cleaned:
        raise ConfigError(f"{label} is required")
    parsed = urlparse(cleaned)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        raise ConfigError(f"{label} must be a valid URL, got {url!r}")
    host = (parsed.hostname or "").lower()
    if parsed.scheme == "http" and host not in {"localhost", "127.0.0.1", "::1"}:
        raise ConfigError(
            f"{label} must use HTTPS for non-local endpoints to protect credentials"
        )
    return cleaned


@dataclass(frozen=True, slots=True)
class CollectorConfig:
    """Validated runtime settings for the Log Sentinel collector."""

    ingest_url: str
    heartbeat_url: str
    device_id: str
    device_name: str
    collector_token: str
    source_type: str = "auth_log"
    log_path: Path = Path("/var/log/auth.log")
    poll_interval_seconds: float = 2.0
    batch_size: int = 25
    heartbeat_interval_seconds: float = 30.0
    state_db_path: Path = Path("./data/collector_state.sqlite3")
    local_log_file: Path | None = Path("./data/collector.log")
    rules_config_path: Path | None = None
    start_at_end: bool = True
    dry_run: bool = False


def load_collector_config(
    env_file: Path | str | None = None,
    *,
    dry_run: bool = False,
    start_at_end_override: bool | None = None,
) -> CollectorConfig:
    """Load and validate collector settings from environment variables or a .env file."""
    if env_file:
        load_dotenv(dotenv_path=Path(env_file), override=False)
    else:
        load_dotenv(override=False)

    device_id_raw = os.getenv("LOG_SENTINEL_DEVICE_ID", "").strip()
    try:
        device_id = str(uuid.UUID(device_id_raw))
    except ValueError as exc:
        raise ConfigError(
            "LOG_SENTINEL_DEVICE_ID must be a valid UUID"
        ) from exc

    device_name = os.getenv("LOG_SENTINEL_DEVICE_NAME", "linux-host").strip() or "linux-host"
    collector_token = os.getenv("LOG_SENTINEL_COLLECTOR_TOKEN", "").strip()

    if not dry_run:
        ingest_url = _validate_endpoint_url(
            os.getenv("LOG_SENTINEL_INGEST_URL", ""), "LOG_SENTINEL_INGEST_URL"
        )
        heartbeat_url = _validate_endpoint_url(
            os.getenv("LOG_SENTINEL_HEARTBEAT_URL", ""), "LOG_SENTINEL_HEARTBEAT_URL"
        )
        if len(collector_token) < 16:
            raise ConfigError(
                "LOG_SENTINEL_COLLECTOR_TOKEN is missing or too short (expected >= 16 chars)"
            )
    else:
        ingest_url = os.getenv("LOG_SENTINEL_INGEST_URL", "https://dry-run.local/ingest").strip()
        heartbeat_url = os.getenv("LOG_SENTINEL_HEARTBEAT_URL", "https://dry-run.local/heartbeat").strip()

    source_type = os.getenv("LOG_SENTINEL_SOURCE_TYPE", "auth_log").strip().lower()
    if source_type not in {"auth_log", "journal"}:
        raise ConfigError(
            f"Unsupported LOG_SENTINEL_SOURCE_TYPE {source_type!r}; expected 'auth_log' or 'journal'"
        )

    log_path = Path(os.getenv("LOG_SENTINEL_LOG_PATH", "/var/log/auth.log").strip())
    poll_interval = max(0.2, float(os.getenv("LOG_SENTINEL_POLL_INTERVAL_SECONDS", "2")))
    batch_size = max(1, min(100, int(os.getenv("LOG_SENTINEL_BATCH_SIZE", "25"))))
    heartbeat_interval = max(
        5.0, float(os.getenv("LOG_SENTINEL_HEARTBEAT_INTERVAL_SECONDS", "30"))
    )
    state_db_path = Path(
        os.getenv("LOG_SENTINEL_STATE_DB_PATH", "./data/collector_state.sqlite3").strip()
    )

    raw_local_log = os.getenv("LOG_SENTINEL_LOCAL_LOG_FILE", "./data/collector.log").strip()
    local_log_file = Path(raw_local_log) if raw_local_log else None

    raw_rules = os.getenv("LOG_SENTINEL_RULES_CONFIG", "").strip()
    rules_config_path = Path(raw_rules) if raw_rules else None

    env_start_at_end = os.getenv("LOG_SENTINEL_START_AT_END", "true").strip().lower() not in {
        "0",
        "false",
        "no",
    }
    start_at_end = (
        start_at_end_override if start_at_end_override is not None else env_start_at_end
    )

    return CollectorConfig(
        ingest_url=ingest_url,
        heartbeat_url=heartbeat_url,
        device_id=device_id,
        device_name=device_name,
        collector_token=collector_token,
        source_type=source_type,
        log_path=log_path,
        poll_interval_seconds=poll_interval,
        batch_size=batch_size,
        heartbeat_interval_seconds=heartbeat_interval,
        state_db_path=state_db_path,
        local_log_file=local_log_file,
        rules_config_path=rules_config_path,
        start_at_end=start_at_end,
        dry_run=dry_run,
    )
