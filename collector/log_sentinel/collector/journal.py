"""Optional systemd journal reader using non-blocking subprocess polling."""

from __future__ import annotations

from collections import deque
import logging
import subprocess
import threading

from log_sentinel.collector.tailer import TailedLine

logger = logging.getLogger("log_sentinel.journal")


class JournalTailer:
    """
    Follows authentication-related systemd journal records via `journalctl`.

    Uses a fixed argument vector (never shell=True) and runs without root when
    the collector service user belongs to the `systemd-journal` group.
    """

    def __init__(self) -> None:
        self._proc: subprocess.Popen[str] | None = None
        self._buffer: deque[str] = deque(maxlen=2000)
        self._lock = threading.Lock()
        self._line_number = 0
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._proc is not None:
            return
        cmd = [
            "journalctl",
            "-f",
            "-n",
            "0",
            "-o",
            "short-iso",
            "SYSLOG_FACILITY=4",
            "SYSLOG_FACILITY=10",
        ]
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except OSError as exc:
            logger.error("Failed to start journalctl: %s", exc)
            self._proc = None
            return

        self._thread = threading.Thread(target=self._reader_loop, daemon=True)
        self._thread.start()

    def _reader_loop(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        for line in self._proc.stdout:
            with self._lock:
                self._buffer.append(line.rstrip("\r\n"))

    def read_new_lines(self) -> list[TailedLine]:
        if self._proc is None:
            self.start()
        out: list[TailedLine] = []
        with self._lock:
            while self._buffer:
                self._line_number += 1
                out.append(
                    TailedLine(
                        line_number=self._line_number,
                        byte_offset=self._line_number,
                        inode=0,
                        text=self._buffer.popleft(),
                    )
                )
        return out

    def stop(self) -> None:
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None
