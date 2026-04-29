import json
import time
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class LogMonitor:

    def __init__(self, log_path: str, window_manager):
        self.log_path = log_path
        self.window_manager = window_manager  # we'll build this next
        self._running = False

    def _wait_for_file(self):
        path = Path(self.log_path)
        while not path.exists():
            logger.info(f"Waiting for log file at {self.log_path}...")
            time.sleep(2)
        logger.info(f"Log file found at {self.log_path}")

    def _parse_line(self, line: str) -> dict | None:
        line = line.strip()
        if not line:
            return None

        try:
            entry = json.loads(line)

            # Validate all required fields are present
            required = ["source_ip", "timestamp", "method",
                        "path", "status", "response_size"]
            if not all(k in entry for k in required):
                logger.warning(f"Log line missing fields: {line}")
                return None

            return {
                "ip":        entry["source_ip"],
                "timestamp": entry["timestamp"],
                "method":    entry["method"],
                "path":      entry["path"],
                "status":    int(entry["status"]),
                "size":      int(entry["response_size"]),
            }

        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Failed to parse log line: {e} | line: {line}")
            return None

    def tail(self):
        self._wait_for_file()
        self._running = True

        with open(self.log_path, "r") as f:
            # Seek to end of file — we don't want to reprocess old lines
            f.seek(0, 2)
            logger.info("Log monitor started — watching for new entries")

            while self._running:
                line = f.readline()

                if line:
                    # We got a new line — parse and process it
                    entry = self._parse_line(line)
                    if entry:
                        self.window_manager.record(entry)
                else:
                    # No new line yet — wait a tiny bit before trying again
                    # 0.1s sleep means we check 10 times per second
                    time.sleep(0.1)

    def stop(self):
        self._running = False
