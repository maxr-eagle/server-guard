import time
import logging
import threading

logger = logging.getLogger(__name__)


class AnomalyDetector:

    def __init__(self, config: dict, window, baseline, blocker, notifier):
        self.config   = config
        self.window   = window
        self.baseline = baseline
        self.blocker  = blocker
        self.notifier = notifier

        # Detection thresholds from config
        self.z_threshold      = config["z_score_threshold"]     # 3.0
        self.rate_multiplier  = config["rate_multiplier"]        # 5
        self.error_multiplier = config["error_rate_multiplier"]  # 3
        self.error_z_score    = config["error_surge_z_score"]    # 1.5
        self._last_global_alert    = 0
        self._global_alert_cooldown = 60  # secs

        self._running = False

    def start(self):
        """Start the detector in a background thread."""
        self._running = True
        thread = threading.Thread(target=self._run, daemon=True)
        thread.start()
        logger.info("Anomaly detector started")

    def _run(self):
        """Main detection loop — runs every 5 seconds."""
        while self._running:
            try:
                self._check_all()
            except Exception as e:
                # Never let the detector crash — log and keep going
                logger.error(f"Detector error: {e}")
            time.sleep(5)

    def _check_all(self):
        mean, stddev = self.baseline.get_effective_baseline()

        # --- Global check ---
        global_rate = self.window.get_global_rate()
        global_z    = self._z_score(global_rate, mean, stddev)

        if self._is_anomalous(global_rate, global_z, mean):
            now = time.time()
            if now - self._last_global_alert > self._global_alert_cooldown:
                self._last_global_alert = now
            logger.warning(
                f"GLOBAL ANOMALY | rate={global_rate} "
                f"mean={mean:.2f} z={global_z:.2f}"
            )
            # Global anomaly = Slack alert only, no IP block
            self.notifier.send_global_alert(
                rate=global_rate,
                mean=mean,
                stddev=stddev,
                z_score=global_z
            )

        # --- Per-IP check ---
        top_ips = self.window.get_top_ips(50)  # check top 50 active IPs

        whitelist = self.config.get("whitelist", [])

        for ip, ip_rate in top_ips:
            if ip in whitelist:
                continue

            if self.blocker.is_banned(ip):
                continue

            ip_z = self._z_score(ip_rate, mean, stddev)

            # Check for error surge — tighten threshold if found
            effective_z_threshold = self._effective_threshold(
                ip, mean, stddev
            )

            if self._is_anomalous(ip_rate, ip_z, mean,
                                  z_threshold=effective_z_threshold):
                logger.warning(
                    f"IP ANOMALY | ip={ip} rate={ip_rate} "
                    f"mean={mean:.2f} z={ip_z:.2f} "
                    f"threshold={effective_z_threshold}"
                )
                self.blocker.ban(ip, ip_rate, mean, stddev, ip_z)

    def _z_score(self, rate: float, mean: float, stddev: float) -> float:
        """Calculate how many standard deviations rate is from mean."""
        return (rate - mean) / stddev

    def _is_anomalous(self, rate: float, z: float, mean: float,
                      z_threshold: float = None) -> bool:
        if z_threshold is None:
            z_threshold = self.z_threshold

        z_fired    = z > z_threshold
        rate_fired = rate > (self.rate_multiplier * mean)

        return z_fired or rate_fired

    def _effective_threshold(self, ip: str, mean: float,
                             stddev: float) -> float:
        error_rate          = self.window.get_ip_error_rate(ip)
        baseline_error_rate = mean * 0.1  # assume ~10% of traffic is errors normally

        if error_rate > (self.error_multiplier * baseline_error_rate):
            logger.info(
                f"Error surge detected for {ip} | "
                f"error_rate={error_rate} threshold tightened to "
                f"{self.error_z_score}"
            )
            return self.error_z_score  # tightened: 1.5

        return self.z_threshold  # normal: 3.0
