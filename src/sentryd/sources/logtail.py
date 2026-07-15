"""Log file source: replay or follow (tail -f) a JSON-lines traffic log.

Each line is a JSON object describing one network record — the shape many
sensors (or a quick export script) can produce:

    {"ts": 1700000000.5, "protocol": "tcp", "src_ip": "10.0.0.5",
     "dst_ip": "10.0.0.9", "src_port": 40123, "dst_port": 443,
     "tcp_flags": "S", "length": 60}

Field notes: ``ts`` accepts an epoch float or an ISO-8601 string and
defaults to the current time; everything else defaults to unknown/empty.
Lines that aren't valid JSON objects are counted and skipped — a log file
mixing other output stays usable.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from sentryd.core.events import Event
from sentryd.sources.base import SourceError

log = logging.getLogger(__name__)


def parse_line(line: str) -> Event | None:
    line = line.strip()
    if not line:
        return None
    try:
        record = json.loads(line)
        if not isinstance(record, dict):
            raise ValueError("not a JSON object")
        return Event(
            ts=_parse_ts(record.get("ts")),
            protocol=str(record.get("protocol", "other")).lower(),
            length=int(record.get("length", 0)),
            src_ip=record.get("src_ip"),
            dst_ip=record.get("dst_ip"),
            src_port=_opt_int(record.get("src_port")),
            dst_port=_opt_int(record.get("dst_port")),
            tcp_flags=str(record.get("tcp_flags", "")),
            summary=line[:200],
        )
    except (ValueError, TypeError) as exc:
        log.debug("skipping unparseable log line (%s): %.120s", exc, line)
        return None


def _parse_ts(value) -> float:
    if value is None:
        return time.time()
    if isinstance(value, (int, float)):
        return float(value)
    return datetime.fromisoformat(str(value)).timestamp()


def _opt_int(value) -> int | None:
    return None if value is None else int(value)


class LogTailSource:
    """Reads a JSON-lines log; optionally keeps following it for new lines.

    ``follow=False`` reads the existing content and stops (useful for replay
    and tests); ``follow=True`` then waits for appended lines like tail -f.
    ``from_start=False`` skips existing content and only watches for new
    lines — classic tail semantics.
    """

    def __init__(
        self,
        path: str | Path,
        follow: bool = True,
        from_start: bool = True,
        poll_interval: float = 0.5,
    ) -> None:
        self.path = Path(path)
        self.follow = follow
        self.from_start = from_start
        self.poll_interval = poll_interval
        self.skipped_lines = 0

    def events(self) -> Iterator[Event]:
        if not self.path.is_file():
            raise SourceError(f"log file not found: {self.path}")

        handle = self.path.open("r", errors="replace")
        try:
            if not self.from_start:
                handle.seek(0, 2)  # jump to EOF: only new lines count
            while True:
                line = handle.readline()
                if not line:
                    if not self.follow:
                        return
                    if self._should_reopen(handle):
                        # logrotate renamed/recreated or truncated the file;
                        # switch to the new content from its beginning.
                        handle.close()
                        handle = self.path.open("r", errors="replace")
                        log.info("log file %s rotated — following new file", self.path)
                        continue
                    time.sleep(self.poll_interval)
                    continue
                event = parse_line(line)
                if event is not None:
                    yield event
                elif line.strip():
                    self.skipped_lines += 1
        finally:
            handle.close()

    def _should_reopen(self, handle) -> bool:
        """True when the path now points at a different or truncated file.

        Detects both logrotate styles: rename-and-recreate (inode changes)
        and copytruncate (size drops below our read offset).
        """
        try:
            on_disk = os.stat(self.path)
        except FileNotFoundError:
            return False  # mid-rotation; keep waiting on the old handle
        opened = os.fstat(handle.fileno())
        return on_disk.st_ino != opened.st_ino or on_disk.st_size < handle.tell()
