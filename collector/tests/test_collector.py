"""Unit and integration tests for Phase 6 Python collector agent."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from log_sentinel.__main__ import main as cli_main
from log_sentinel.collector.agent import LogSentinelAgent
from log_sentinel.collector.tailer import FileTailer
from log_sentinel.config.settings import CollectorConfig, ConfigError, load_collector_config
from log_sentinel.ingestion.client import DeliveryResult
from log_sentinel.ingestion.spool import LocalSpool, compute_backoff_seconds

DEVICE_ID = "11111111-1111-4111-8111-111111111111"
TOKEN = "collector-secret-token-for-tests-1234"


class StubIngestionClient:
    """In-memory stub simulating cloud success, temporary outages, and permanent errors."""

    def __init__(self, fail_mode: str | None = None) -> None:
        self.fail_mode = fail_mode
        self.batches_sent: list[dict] = []
        self.heartbeats_sent: list[dict] = []

    def send_batch(self, payload: dict) -> DeliveryResult:
        if self.fail_mode == "network":
            return DeliveryResult(ok=False, retryable=True, status_code=None, message="Network down")
        if self.fail_mode == "unauthorized":
            return DeliveryResult(ok=False, retryable=False, status_code=401, message="HTTP 401: Invalid")
        self.batches_sent.append(payload)
        return DeliveryResult(
            ok=True,
            retryable=False,
            status_code=200,
            message="ok",
            accepted_count=len(payload.get("events", [])),
            duplicate_count=0,
        )

    def send_heartbeat(self, *, collector_version: str, os_info: str) -> DeliveryResult:
        if self.fail_mode == "network":
            return DeliveryResult(ok=False, retryable=True, status_code=None, message="Network down")
        self.heartbeats_sent.append({"version": collector_version, "os_info": os_info})
        return DeliveryResult(ok=True, retryable=False, status_code=200, message="ok")

    def close(self) -> None:
        pass


def test_config_validation_enforces_https_and_uuid(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("LOG_SENTINEL_DEVICE_ID", "not-a-uuid")
    with pytest.raises(ConfigError):
        load_collector_config()

    monkeypatch.setenv("LOG_SENTINEL_DEVICE_ID", DEVICE_ID)
    monkeypatch.setenv("LOG_SENTINEL_COLLECTOR_TOKEN", TOKEN)
    monkeypatch.setenv("LOG_SENTINEL_INGEST_URL", "http://example.com/ingest")
    monkeypatch.setenv("LOG_SENTINEL_HEARTBEAT_URL", "https://example.com/hb")
    with pytest.raises(ConfigError):
        load_collector_config()

    # Localhost HTTP is permitted for local dev/testing
    monkeypatch.setenv("LOG_SENTINEL_INGEST_URL", "http://127.0.0.1:54321/ingest")
    monkeypatch.setenv("LOG_SENTINEL_STATE_DB_PATH", str(tmp_path / "state.sqlite3"))
    cfg = load_collector_config()
    assert cfg.device_id == DEVICE_ID
    assert cfg.batch_size == 25


def test_tailer_incremental_partial_lines_and_restart_persistence(tmp_path: Path):
    log_file = tmp_path / "auth.log"
    log_file.write_text("Nov 26 21:40:00 host sshd[1]: Server listening on 0.0.0.0 port 22.\n", encoding="utf-8")
    db_path = tmp_path / "spool.sqlite3"

    spool1 = LocalSpool(db_path)
    tailer1 = FileTailer(log_file, spool1, start_at_end=True)

    # First poll with start_at_end=True skips pre-existing lines
    assert tailer1.read_new_lines() == []

    # Append partial line (no newline yet) -> must buffer cleanly
    with log_file.open("ab") as fh:
        fh.write(b"Nov 26 21:41:01 host sshd[2]: Failed password ")
    assert tailer1.read_new_lines() == []

    # Complete the line and add another
    with log_file.open("ab") as fh:
        fh.write(b"for admin from 203.0.113.55 port 40001 ssh2\n")
        fh.write(b"Nov 26 21:41:05 host sshd[3]: Failed password for admin from 203.0.113.55 port 40002 ssh2\n")

    read1 = tailer1.read_new_lines()
    assert len(read1) == 2
    assert "port 40001" in read1[0].text
    assert "port 40002" in read1[1].text
    spool1.close()

    # Simulate collector restart: must resume from persisted offset and not reread old lines
    spool2 = LocalSpool(db_path)
    tailer2 = FileTailer(log_file, spool2, start_at_end=False)
    assert tailer2.read_new_lines() == []

    with log_file.open("ab") as fh:
        fh.write(b"Nov 26 21:41:10 host sshd[4]: Accepted publickey for deploy from 198.51.100.10 port 50000 ssh2\n")
    read2 = tailer2.read_new_lines()
    assert len(read2) == 1
    assert "deploy" in read2[0].text
    spool2.close()


def test_tailer_handles_log_rotation_and_truncation(tmp_path: Path):
    log_file = tmp_path / "auth.log"
    rotated_file = tmp_path / "auth.log.1"
    log_file.write_text(
        "Nov 26 21:40:01 host sshd[1]: Failed password for admin from 203.0.113.55 port 1 ssh2\n"
        "Nov 26 21:40:02 host sshd[2]: Failed password for admin from 203.0.113.55 port 2 ssh2\n",
        encoding="utf-8",
    )
    spool = LocalSpool(tmp_path / "spool.sqlite3")
    tailer = FileTailer(log_file, spool, start_at_end=False)
    assert len(tailer.read_new_lines()) == 2

    # Rotate file (rename + create smaller new file)
    log_file.rename(rotated_file)
    assert tailer.read_new_lines() == []  # Missing file mid-rotation must not crash

    log_file.write_text(
        "Nov 26 21:42:00 host sshd[9]: Accepted password for ops from 198.51.100.9 port 22 ssh2\n",
        encoding="utf-8",
    )
    rotated_read = tailer.read_new_lines()
    assert len(rotated_read) == 1
    assert "ops" in rotated_read[0].text
    spool.close()


def test_spool_backoff_and_queue_bound(tmp_path: Path):
    assert compute_backoff_seconds(1) == 2.0
    assert compute_backoff_seconds(3) == 8.0
    assert compute_backoff_seconds(20) == 300.0

    spool = LocalSpool(tmp_path / "spool.sqlite3", max_queued_batches=3)
    for i in range(5):
        spool.enqueue_batch({"idx": i})
    assert spool.pending_count() == 3
    due = spool.get_due_batches()
    assert [b.payload["idx"] for b in due] == [2, 3, 4]
    spool.close()


def test_agent_offline_retry_and_incident_delivery(tmp_path: Path):
    log_file = tmp_path / "auth.log"
    lines = [
        f"Nov 26 21:41:0{i} ubuntu sshd[21{i}]: Failed password for admin from 203.0.113.55 port 4000{i} ssh2"
        for i in range(5)
    ]
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    cfg = CollectorConfig(
        ingest_url="https://example.supabase.co/functions/v1/ingest-events",
        heartbeat_url="https://example.supabase.co/functions/v1/collector-heartbeat",
        device_id=DEVICE_ID,
        device_name="ubuntu-test",
        collector_token=TOKEN,
        source_type="auth_log",
        log_path=log_file,
        state_db_path=tmp_path / "state.sqlite3",
        local_log_file=None,
        start_at_end=False,
        heartbeat_interval_seconds=30.0,
    )

    stub_client = StubIngestionClient(fail_mode="network")
    agent = LogSentinelAgent(cfg, client=stub_client)  # type: ignore[arg-type]

    # Run 1: network is down -> batch queued locally in SQLite, heartbeat fails gracefully
    res1 = agent.run_once()
    assert res1["events_parsed"] == 5
    assert res1["batches_queued"] == 1
    assert res1["batches_delivered"] == 0
    assert agent.spool.pending_count() == 1

    # Network recovers; advance retry timer past backoff and flush
    stub_client.fail_mode = None
    agent.spool._conn.execute("UPDATE pending_batches SET next_retry_at = 0")
    agent.spool._conn.commit()
    # Second run_once inside 30s interval must NOT send duplicate heartbeat
    res2 = agent.run_once()
    assert res2["batches_delivered"] == 1
    assert res2["heartbeat_sent"] == 0
    assert agent.spool.pending_count() == 0

    assert len(stub_client.batches_sent) == 1
    sent_payload = stub_client.batches_sent[0]
    assert len(sent_payload["events"]) == 5
    assert len(sent_payload["incidents"]) == 1
    assert sent_payload["incidents"][0]["rule_id"] == "RULE_001"
    agent.spool.close()


def test_agent_drops_non_retryable_401_and_supports_cli_dry_run(monkeypatch, tmp_path: Path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Nov 26 21:41:01 ubuntu sshd[1]: Accepted publickey for deploy from 198.51.100.10 port 51200 ssh2\n",
        encoding="utf-8",
    )

    # Verify non-retryable 401 drops batch rather than looping forever
    cfg = CollectorConfig(
        ingest_url="https://example.supabase.co/functions/v1/ingest-events",
        heartbeat_url="https://example.supabase.co/functions/v1/collector-heartbeat",
        device_id=DEVICE_ID,
        device_name="ubuntu-test",
        collector_token=TOKEN,
        log_path=log_file,
        state_db_path=tmp_path / "state.sqlite3",
        local_log_file=None,
        start_at_end=False,
    )
    agent = LogSentinelAgent(cfg, client=StubIngestionClient(fail_mode="unauthorized"))  # type: ignore[arg-type]
    res = agent.run_once()
    assert res["batches_queued"] == 1
    assert agent.spool.pending_count() == 0
    agent.spool.close()

    # Verify CLI --once --dry-run exits cleanly
    monkeypatch.setenv("LOG_SENTINEL_DEVICE_ID", DEVICE_ID)
    monkeypatch.setenv("LOG_SENTINEL_LOG_PATH", str(log_file))
    monkeypatch.setenv("LOG_SENTINEL_STATE_DB_PATH", str(tmp_path / "cli.sqlite3"))
    monkeypatch.setenv("LOG_SENTINEL_LOCAL_LOG_FILE", "")
    exit_code = cli_main(["--once", "--dry-run", "--from-beginning"])
    assert exit_code == 0
