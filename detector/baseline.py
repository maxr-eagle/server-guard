import time
import math
import threading
import logging
from collections import deque

logger = logging.getLogger(__name__)


class BaselineEngine:
    def __init__(self, config: dict):
        self.window_minutes   = config["baseline_window_minutes"]   # 30
        self.recalc_interval  = config["baseline_recalc_interval"]  # 60s
        self.min_data_points  = config["baseline_min_data_points"]  # 10
        self.floor            = config["baseline_floor"]            # 1.0
        self.audit_log_path   = config["audit_log_path"]

        self._max_slots = self.window_minutes * 60
        self._per_second_counts = deque(maxlen=self._max_slots)

        self._current_second = int(time.time())
        self._current_count  = 0

        self._mean   = 0.0
        self._stddev = 1.0

        self._hourly_slots: dict[int, list] = {h: [] for h in range(24)}
        self._hourly_mean:   dict[int, float] = {h: 0.0 for h in range(24)}
        self._hourly_stddev: dict[int, float] = {h: 1.0 for h in range(24)}
        self._hourly_counts: dict[int, int]   = {h: 0   for h in range(24)}

        self._lock = threading.Lock()

        self._last_recalc = time.time()

    def tick(self, count: int):
        now = time.time()
        hour = int(time.strftime("%H"))  # current hour (0-23)

        with self._lock:
            self._per_second_counts.append(count)
            self._hourly_slots[hour].append(count)

            if now - self._last_recalc >= self.recalc_interval:
                self._recalculate(hour)
                self._last_recalc = now


    def get_effective_baseline(self) -> tuple[float, float]:
        hour = int(time.strftime("%H"))

        with self._lock:
            if self._hourly_counts[hour] >= self.min_data_points:
                mean   = self._hourly_mean[hour]
                stddev = self._hourly_stddev[hour]
            else:
                mean   = self._mean
                stddev = self._stddev

        mean   = max(mean, self.floor)
        stddev = max(stddev, self.floor)

        return mean, stddev

    def get_stats(self) -> dict:
        mean, stddev = self.get_effective_baseline()
        hour = int(time.strftime("%H"))
        with self._lock:
            data_points = len(self._per_second_counts)
            hourly_points = self._hourly_counts[hour]
        return {
            "effective_mean":   round(mean, 3),
            "effective_stddev": round(stddev, 3),
            "data_points":      data_points,
            "hourly_points":    hourly_points,
            "current_hour":     hour,
        }


    def _recalculate(self, hour: int):
        if len(self._per_second_counts) >= self.min_data_points:
            self._mean, self._stddev = self._compute_stats(
                list(self._per_second_counts)
            )

        hourly_data = self._hourly_slots[hour]
        if len(hourly_data) >= self.min_data_points:
            self._hourly_mean[hour], self._hourly_stddev[hour] = \
                self._compute_stats(hourly_data)
            self._hourly_counts[hour] = len(hourly_data)

        # Write to audit log
        self._write_audit(hour)

        logger.info(
            f"Baseline recalculated | "
            f"global mean={self._mean:.3f} stddev={self._stddev:.3f} | "
            f"hour={hour} mean={self._hourly_mean[hour]:.3f} "
            f"stddev={self._hourly_stddev[hour]:.3f} | "
            f"data_points={len(self._per_second_counts)}"
        )

    def _compute_stats(self, data: list) -> tuple[float, float]:
        n    = len(data)
        mean = sum(data) / n

        variance = sum((x - mean) ** 2 for x in data) / n
        stddev   = math.sqrt(variance)

        return mean, stddev

    def _write_audit(self, hour: int):
        """Writes a structured audit log entry for baseline recalculation."""
        import os
        os.makedirs(os.path.dirname(self.audit_log_path), exist_ok=True)

        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        line = (
            f"[{timestamp}] BASELINE_RECALC - | "
            f"hour={hour} | "
            f"mean={self._mean:.3f} stddev={self._stddev:.3f} | "
            f"-\n"
        )
        try:
            with open(self.audit_log_path, "a") as f:
                f.write(line)
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")
