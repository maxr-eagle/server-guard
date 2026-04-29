import time
import threading
from collections import deque, defaultdict

class WindowManager:
    """
    Maintains two sliding windows over the last N seconds:
    - One global window (all traffic)
    - One per-IP window (traffic from each source IP)

    A window is a deque of timestamps.
    Eviction happens on every new record — timestamps older
    than window_seconds are popped from the left.
    """

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds

        # Global window — every request regardless of IP
        self._global_window = deque()

        # Per-IP windows — one deque per IP address
        # defaultdict means accessing a new key auto-creates an empty deque
        self._ip_windows: dict[str, deque] = defaultdict(deque)

        # Per-IP error tracking (4xx and 5xx responses)
        self._ip_errors: dict[str, deque] = defaultdict(deque)

        # Lock for thread safety — monitor and detector run in separate threads
        self._lock = threading.Lock()

    def _evict(self, window: deque, now: float):
        """
        Remove all timestamps from the left of the deque
        that are older than window_seconds ago.
        This is what makes it a SLIDING window — old data falls off.
        """
        cutoff = now - self.window_seconds
        while window and window[0] < cutoff:
            window.popleft()

    def record(self, entry: dict):
        """
        Called by LogMonitor for every new log line.
        Records the request in global and per-IP windows.
        """
        now = time.time()  # use Unix timestamp (float) for easy math
        ip = entry["ip"]
        status = entry["status"]

        with self._lock:
            # Add to global window and evict old entries
            self._global_window.append(now)
            self._evict(self._global_window, now)

            # Add to this IP's window and evict old entries
            self._ip_windows[ip].append(now)
            self._evict(self._ip_windows[ip], now)

            # Track errors separately
            if status >= 400:
                self._ip_errors[ip].append(now)
                self._evict(self._ip_errors[ip], now)

    def get_global_rate(self) -> int:
        """Returns number of requests in the last window_seconds globally."""
        now = time.time()
        with self._lock:
            self._evict(self._global_window, now)
            return len(self._global_window)

    def get_ip_rate(self, ip: str) -> int:
        """Returns number of requests from a specific IP in the last window_seconds."""
        now = time.time()
        with self._lock:
            self._evict(self._ip_windows[ip], now)
            return len(self._ip_windows[ip])

    def get_ip_error_rate(self, ip: str) -> int:
        """Returns number of 4xx/5xx responses from an IP in the last window_seconds."""
        now = time.time()
        with self._lock:
            self._evict(self._ip_errors[ip], now)
            return len(self._ip_errors[ip])

    def get_top_ips(self, n: int = 10) -> list[tuple[str, int]]:
        """Returns the top N IPs by request count in the current window."""
        now = time.time()
        with self._lock:
            rates = {}
            for ip, window in self._ip_windows.items():
                self._evict(window, now)
                if window:
                    rates[ip] = len(window)
            # Sort by rate descending, return top N
            return sorted(rates.items(), key=lambda x: x[1], reverse=True)[:n]
