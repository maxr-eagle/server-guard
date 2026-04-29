import time
import threading
import logging

logger = logging.getLogger(__name__)


class Unbanner:
    """
    Runs in a background thread.
    Every 30 seconds, checks all active bans.
    If a ban has expired, calls blocker.unban() to release it.

    Backoff schedule (from config):
    Tier 0: 10 min ban
    Tier 1: 30 min ban
    Tier 2: 2 hour ban
    Tier 3+: permanent (never unbanned automatically)
    """

    def __init__(self, blocker, check_interval: int = 30):
        self.blocker        = blocker
        self.check_interval = check_interval  # check every 30 seconds
        self._running       = False

    def start(self):
        """Start the unbanner in a background thread."""
        self._running = True
        thread = threading.Thread(target=self._run, daemon=True)
        thread.start()
        logger.info("Unbanner started")

    def _run(self):
        """
        Main loop — checks for expired bans every 30 seconds.
        We check frequently (30s) so bans expire close to on time
        even though we don't use per-ban timers.
        """
        while self._running:
            try:
                self._check_expired()
            except Exception as e:
                logger.error(f"Unbanner error: {e}")
            time.sleep(self.check_interval)

    def _check_expired(self):
        """
        Look at every active ban.
        If current time > banned_at + duration → unban.
        Permanent bans (duration=None) are never auto-unbanned.
        """
        now      = time.time()
        bans     = self.blocker.get_active_bans()

        for ip, ban_info in bans.items():
            # Skip permanent bans
            if ban_info.get("permanent"):
                continue

            banned_at = ban_info["banned_at"]
            duration  = ban_info["duration"]

            # Has the ban duration elapsed?
            if now >= banned_at + duration:
                elapsed = int(now - banned_at)
                logger.info(
                    f"Ban expired for {ip} | "
                    f"elapsed={elapsed}s duration={duration}s"
                )
                self.blocker.unban(ip)
