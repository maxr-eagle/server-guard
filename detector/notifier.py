import time
import logging
import requests

logger = logging.getLogger(__name__)


class Notifier:
    """
    Sends formatted Slack alerts via webhook.
    Every alert includes: condition, current rate,
    baseline, timestamp, and ban duration where applicable.
    """

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    # ------------------------------------------------------------------ #
    #  Public methods — called by detector and blocker                    #
    # ------------------------------------------------------------------ #

    def send_ban_alert(self, ip: str, rate: float, mean: float,
                       stddev: float, z_score: float, duration: int | None):
        """Fired when an IP is banned."""
        duration_str = f"{duration // 60} minutes" if duration else "PERMANENT"
        timestamp    = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

        payload = {
            "blocks": [
                self._header("🚨 IP BANNED"),
                self._section(
                    f"*IP Address:* `{ip}`\n"
                    f"*Condition:* Z-score or rate threshold exceeded\n"
                    f"*Current Rate:* {rate} req/60s\n"
                    f"*Baseline Mean:* {mean:.2f} req/s\n"
                    f"*Baseline Stddev:* {stddev:.2f}\n"
                    f"*Z-Score:* {z_score:.2f}\n"
                    f"*Ban Duration:* {duration_str}\n"
                    f"*Timestamp:* {timestamp}"
                ),
                self._divider()
            ]
        }
        self._send(payload)
        logger.info(f"Slack ban alert sent for {ip}")

    def send_unban_alert(self, ip: str, next_tier: int,
                         next_duration: int | None):
        """Fired when an IP ban expires."""
        next_str  = f"{next_duration // 60} minutes" \
                    if next_duration else "PERMANENT"
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

        payload = {
            "blocks": [
                self._header("✅ IP UNBANNED"),
                self._section(
                    f"*IP Address:* `{ip}`\n"
                    f"*Condition:* Ban timer expired\n"
                    f"*Next Ban Duration (if reoffends):* {next_str}\n"
                    f"*Timestamp:* {timestamp}"
                ),
                self._divider()
            ]
        }
        self._send(payload)
        logger.info(f"Slack unban alert sent for {ip}")

    def send_global_alert(self, rate: float, mean: float,
                          stddev: float, z_score: float):
        """Fired when global traffic is anomalous — no IP block."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

        payload = {
            "blocks": [
                self._header("⚠️ GLOBAL TRAFFIC ANOMALY"),
                self._section(
                    f"*Condition:* Global request rate anomalous\n"
                    f"*Current Rate:* {rate} req/60s\n"
                    f"*Baseline Mean:* {mean:.2f} req/s\n"
                    f"*Baseline Stddev:* {stddev:.2f}\n"
                    f"*Z-Score:* {z_score:.2f}\n"
                    f"*Action:* Alert only — no IP block possible\n"
                    f"*Timestamp:* {timestamp}"
                ),
                self._divider()
            ]
        }
        self._send(payload)
        logger.info(f"Slack global alert sent | rate={rate} z={z_score:.2f}")

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                   #
    # ------------------------------------------------------------------ #

    def _send(self, payload: dict):
        """POST the payload to the Slack webhook."""
        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=5
            )
            if response.status_code != 200:
                logger.error(
                    f"Slack webhook error: {response.status_code} "
                    f"{response.text}"
                )
        except requests.exceptions.Timeout:
            logger.error("Slack webhook timed out")
        except Exception as e:
            logger.error(f"Slack webhook failed: {e}")

    def _header(self, text: str) -> dict:
        return {
            "type": "header",
            "text": {"type": "plain_text", "text": text}
        }

    def _section(self, text: str) -> dict:
        return {
            "type": "section",
            "text": {"type": "mrkdwn", "text": text}
        }

    def _divider(self) -> dict:
        return {"type": "divider"}
