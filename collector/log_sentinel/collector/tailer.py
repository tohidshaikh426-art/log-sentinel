"""Continuous log file tailer with persistent cursor and log-rotation recovery."""

from __future__ import annotations

from dataclasses import dataclass
import logging
import os
from pathlib import Path

from log_sentinel.ingestion.spool import LocalSpool

logger = logging.getLogger("log_sentinel.tailer")


@dataclass(frozen=True, slots=True)
class TailedLine:
    """Single complete log line with stable file position metadata."""

    line_number: int
    byte_offset: int
    inode: int
    text: str


class FileTailer:
    """
    Incrementally tails a log file without rereading already-processed bytes.

    Tracks (inode, byte_offset, line_number) in SQLite so collector restarts
    resume cleanly and logrotate rotations/truncations are handled safely.
    """

    def __init__(
        self,
        file_path: Path | str,
        spool: LocalSpool,
        *,
        start_at_end: bool = True,
    ) -> None:
        self.file_path = Path(file_path)
        self.spool = spool
        self.start_at_end = start_at_end

    def read_new_lines(self, max_bytes: int = 1024 * 1024) -> list[TailedLine]:
        """Read any newly appended complete lines since the saved cursor."""
        try:
            st = os.stat(self.file_path)
        except FileNotFoundError:
            return []
        except PermissionError:
            logger.error(
                "Permission denied reading %s. Add collector user to 'adm' group (no root needed).",
                self.file_path,
            )
            return []
        except OSError as exc:
            logger.warning("Unable to stat %s: %s", self.file_path, exc)
            return []

        inode = int(st.st_ino)
        file_size = int(st.st_size)
        cursor = self.spool.get_cursor(self.file_path)

        if cursor is None:
            initial_offset = file_size if self.start_at_end else 0
            self.spool.save_cursor(self.file_path, inode, initial_offset, 0)
            if self.start_at_end:
                return []
            byte_offset = 0
            line_number = 0
        else:
            byte_offset = cursor.byte_offset
            line_number = cursor.line_number
            # Detect logrotate (new inode) or copytruncate (file shrunk)
            if (inode != 0 and cursor.inode != 0 and inode != cursor.inode) or (
                file_size < cursor.byte_offset
            ):
                logger.info(
                    "Detected log rotation or truncation for %s (old inode=%s offset=%s -> new inode=%s size=%s)",
                    self.file_path,
                    cursor.inode,
                    cursor.byte_offset,
                    inode,
                    file_size,
                )
                byte_offset = 0
                line_number = 0
                self.spool.save_cursor(self.file_path, inode, 0, 0)

        if file_size <= byte_offset:
            return []

        try:
            with self.file_path.open("rb") as handle:
                handle.seek(byte_offset)
                chunk = handle.read(max_bytes)
        except OSError as exc:
            logger.warning("Failed reading %s: %s", self.file_path, exc)
            return []

        if not chunk:
            return []

        # Only consume up to the final newline so partial writes wait for next poll
        last_newline = chunk.rfind(b"\n")
        if last_newline == -1:
            return []

        complete_block = chunk[: last_newline + 1]
        lines_out: list[TailedLine] = []
        rel_offset = 0

        for raw_line in complete_block.splitlines(keepends=True):
            line_offset = byte_offset + rel_offset
            rel_offset += len(raw_line)
            line_number += 1
            decoded = raw_line.rstrip(b"\r\n").decode("utf-8", errors="replace")
            lines_out.append(
                TailedLine(
                    line_number=line_number,
                    byte_offset=line_offset,
                    inode=inode,
                    text=decoded,
                )
            )

        new_offset = byte_offset + len(complete_block)
        self.spool.save_cursor(self.file_path, inode, new_offset, line_number)
        return lines_out
