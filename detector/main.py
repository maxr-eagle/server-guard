import time
import logging
import threading
import yaml

from monitor        import LogMonitor
from monitor_window import WindowManager
from baseline       import BaselineEngine
from detector       import AnomalyDetector
from blocker        import Blocker
from unbanner       import Unbanner
from notifier       import Notifier
from dashboard      import Dashboard

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)


def main():
    with open("config.yaml") as f:
        config = yaml.safe_load(f)

    audit_log = config["audit_log_path"]

    # Build the stack
    window    = WindowManager(window_seconds=config["window_seconds"])
    baseline  = BaselineEngine(config=config)
    notifier  = Notifier(webhook_url=config["slack_webhook_url"])
    blocker   = Blocker(config=config, notifier=notifier,
                        audit_log_path=audit_log)
    unbanner  = Unbanner(blocker=blocker)
    detector  = AnomalyDetector(
        config=config, window=window,
        baseline=baseline, blocker=blocker, notifier=notifier
    )
    dashboard = Dashboard(
        config=config, window=window,
        baseline=baseline, blocker=blocker
    )

    # Baseline ticker
    def baseline_ticker():
        while True:
            time.sleep(1)
            baseline.tick(window.get_global_rate())

    # Stats printer
    def print_stats():
        while True:
            time.sleep(10)
            rate         = window.get_global_rate()
            mean, stddev = baseline.get_effective_baseline()
            top_ips      = window.get_top_ips(3)
            bans         = blocker.get_active_bans()
            z = (rate - mean) / stddev if stddev > 0 else 0.0
            logger.info(
                f"rate={rate} | mean={mean:.2f} stddev={stddev:.2f} | "
                f"z={z:.2f} | bans={len(bans)} | top_ips={top_ips}"
            )

    # Start everything
    threading.Thread(target=baseline_ticker, daemon=True).start()
    threading.Thread(target=print_stats,     daemon=True).start()
    unbanner.start()
    detector.start()
    dashboard.start()

    # Main loop — tails the log file forever
    monitor = LogMonitor(
        log_path=config["log_path"],
        window_manager=window
    )
    logger.info("Server Guard fully started")
    monitor.tail()


if __name__ == "__main__":
    main()
