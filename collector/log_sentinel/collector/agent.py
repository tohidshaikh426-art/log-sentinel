"""Main Log Sentinel collector daemon orchestrating tailing, detection, retries, and heartbeats."""

from __future__ import annotations

from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
import platform
import signal
import time
from typing import Any

import log_sentinel
from log_sentinel.collector.journal import JournalTailer
from log_sentinel.collector.tailer import FileTailer, TailedLine
from log_sentinel.config.settings import CollectorConfig
from log_sentinel.detection.engine import DetectionEngine
from log_sentinel.ingestion.client import IngestionClient
from log_sentinel.ingestion.spool import LocalSpool
from log_sentinel.parser.models import NormalizedEvent
from log_sentinel.parser.syslog_auth import parse_auth_log_line

logger = logging.getLogger("log_sentinel.agent")


def configure_logging(config: CollectorConfig) -> None:
    """Set up local console and optional rotating file logging."""
    root = logging.getLogger("log_sentinel")
    if root.handlers:
        return
    root.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(fmt)
    root.addHandler(stream_handler)

    if config.local_log_file:
        config.local_log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            config.local_log_file, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"
        )
        file_handler.setFormatter(fmt)
        root.addHandler(file_handler)


class LogSentinelAgent:
    """Continuously monitors logs, detects threats, and forwards batches resiliently."""

    def __init__(
        self,
        config: CollectorConfig,
        *,
        spool: LocalSpool | None = None,
        client: IngestionClient | None = None,
        engine: DetectionEngine | None = None,
    ) -> None:
        self.config = config
        self.spool = spool or LocalSpool(config.state_db_path)
        self.client = client or IngestionClient(
            ingest_url=config.ingest_url,
            heartbeat_url=config.heartbeat_url,
            device_id=config.device_id,
            collector_token=config.collector_token,
        )
        self.engine = engine or DetectionEngine(config_path=config.rules_config_path)

        self._tailer: FileTailer | JournalTailer = (
            JournalTailer()
            if config.source_type == "journal"
            else FileTailer(
                config.log_path,
                self.spool,
                start_at_end=config.start_at_end,
            )
        )
        self._local_tz = datetime.now().astimezone().tzinfo
        self._os_info = f"{platform.system()} {platform.release()}"
        self._stop_requested = False
        self._last_heartbeat_mono = 0.0

    def request_shutdown(self, *_args: Any) -> None:
        """Signal handler for graceful SIGINT/SIGTERM shutdown."""
        logger.info("Shutdown signal received; finishing current cycle...")
        self._stop_requested = True

    def _parse_tailed_lines(self, tailed: list[TailedLine]) -> list[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        for item in tailed:
            hint = f"{self.config.source_type}:{item.inode}:{item.byte_offset}"
            ev, err = parse_auth_log_line(
                item.text,
                device_id=self.config.device_id,
                local_tz=self._local_tz,
                is_simulated=False,
                position_hint=hint,
            )
            if ev is not None:
                events.append(ev)
            elif err is not None:
                logger.warning("Line %s skipped (%s)", item.line_number, err)
        return events

    def _enqueue_events_and_incidents(self, events: list[NormalizedEvent]) -> int:
        if not events:
            return 0

        incidents = self.engine.process_events(events)
        if self.config.dry_run:
            logger.info(
                "[DRY RUN] Parsed %d event(s), detected %d incident(s)",
                len(events),
                len(incidents),
            )
            return 0

        batch_size = self.config.batch_size
        queued = 0
        for idx in range(0, len(events), batch_size):
            chunk_events = events[idx : idx + batch_size]
            chunk_fps = {e.event_fingerprint for e in chunk_events}
            # Attach incidents on the final chunk (or matching chunk)
            is_last_chunk = idx + batch_size >= len(events)
            chunk_incidents = (
                [
                    inc.to_dict()
                    for inc in incidents
                    if is_last_chunk or any(fp in chunk_fps for fp in inc.supporting_fingerprints)
                ]
                if is_last_chunk
                else []
            )
            payload = {
                "collector_version": log_sentinel.__version__,
                "events": [e.to_dict() for e in chunk_events],
                "incidents": chunk_incidents,
            }
            self.spool.enqueue_batch(payload)
            queued += 1
        return queued

    def flush_pending_batches(self, now_ts: float | None = None) -> int:
        """Send due batches from the local SQLite queue; returns delivered batch count."""
        if self.config.dry_run:
            return 0

        delivered = 0
        due = self.spool.get_due_batches(limit=20, now_ts=now_ts)
        for batch in due:
            result = self.client.send_batch(batch.payload)
            if result.ok:
                self.spool.mark_delivered(batch.batch_id)
                delivered += 1
                logger.info(
                    "Delivered batch %d (accepted=%d, duplicates=%d)",
                    batch.batch_id,
                    result.accepted_count,
                    result.duplicate_count,
                )
            elif result.retryable:
                next_at = self.spool.schedule_retry(
                    batch.batch_id, batch.attempts, now_ts=now_ts
                )
                logger.warning(
                    "Batch %d deferred (%s); next retry at epoch %.0f",
                    batch.batch_id,
                    result.message,
                    next_at,
                )
                break
            else:
                logger.error(
                    "Dropping non-retryable batch %d (%s)",
                    batch.batch_id,
                    result.message,
                )
                self.spool.mark_delivered(batch.batch_id)
        return delivered

    def maybe_send_heartbeat(self, mono_now: float | None = None) -> bool:
        """Send a heartbeat if the configured interval has elapsed."""
        if self.config.dry_run:
            return False
        now = time.monotonic() if mono_now is None else mono_now
        if (
            self._last_heartbeat_mono > 0
            and (now - self._last_heartbeat_mono) < self.config.heartbeat_interval_seconds
        ):
            return False

        self._last_heartbeat_mono = now
        res = self.client.send_heartbeat(
            collector_version=log_sentinel.__version__,
            os_info=self._os_info,
        )
        if not res.ok:
            logger.warning("Heartbeat failed: %s", res.message)
            return False
        return True

    def run_once(self) -> dict[str, int]:
        """Execute one poll -> parse -> detect -> flush -> heartbeat cycle."""
        tailed = self._tailer.read_new_lines()
        events = self._parse_tailed_lines(tailed)
        queued = self._enqueue_events_and_incidents(events)
        delivered = self.flush_pending_batches()
        heartbeat_sent = int(self.maybe_send_heartbeat())
        return {
            "lines_read": len(tailed),
            "events_parsed": len(events),
            "batches_queued": queued,
            "batches_delivered": delivered,
            "heartbeat_sent": heartbeat_sent,
        }

    def run_forever(self) -> None:
        """Run the continuous monitoring loop until SIGINT/SIGTERM."""
        signal.signal(signal.SIGINT, self.request_shutdown)
        signal.signal(signal.SIGTERM, self.request_shutdown)
        logger.info(
            "Log Sentinel collector v%s started (device=%s, source=%s, path=%s, dry_run=%s)",
            log_sentinel.__version__,
            self.config.device_name,
            self.config.source_type,
            self.config.log_path,
            self.config.dry_run,
        )

        try:
            while not self._stop_requested:
                try:
                    self.run_once()
                except Exception as exc:  # noqa: BLE001 - daemon loop must survive unexpected errors
                    logger.exception("Unexpected error in collector loop: %s", exc)

                # Sleep in short increments so shutdown signals feel responsive
                deadline = time.monotonic() + self.config.poll_interval_seconds
                while not self._stop_requested and time.monotonic() < deadline:
                    time.sleep(min(0.5, max(0.05, deadline - time.monotonic())))
        finally:
            if isinstance(self._tailer, JournalTailer):
                self._tailer.stop()
            try:
                self.flush_pending_batches()
            except Exception:  # noqa: BLE001
                pass
            self.client.close()
            self.spool.close()
            logger.info("Log Sentinel collector stopped cleanly.")
