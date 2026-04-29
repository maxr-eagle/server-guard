import time
import subprocess
import threading
import logging

logger = logging.getLogger(__name__)


class Blocker:
    """
    Manages iptables bans.
    Adds DROP rules for anomalous IPs and tracks ban state.
    Works with the Unbanner to implement the backoff schedule.
    """

    def __init__(self, config: dict, notifier, audit_log_path: str):
        self.config         = config
        self.notifier       = notifier
        self.audit_log_path = audit_log_path
        self.unban_schedule = config["unban_schedule"]  # [10, 30, 120]

        # Active bans: ip → ban info dict
        # {
        #   "banned_at": timestamp,
        #   "duration":  600,        ← seconds (10 min)
        #   "tier":      0,          ← index into unban_schedule
        #   "rate":      85,
        #   "mean":      12.3,
        # }
        self._bans: dict[str, dict] = {}
        self._lock = threading.Lock()

    def is_banned(self, ip: str) -> bool:
        """Returns True if this IP currently has an active ban."""
        with self._lock:
            return ip in self._bans

    def ban(self, ip: str, rate: float, mean: float,
            stddev: float, z_score: float):
        """
        Add an iptables DROP rule for this IP and record the ban.
        Must complete within 10 seconds — iptables is fast, this is fine.
        """
        with self._lock:
            if ip in self._bans:
                return  # already banned, don't double-ban

            # Determine ban duration from schedule
            # If this IP has been banned before, use next tier
            tier     = self._bans.get(ip, {}).get("tier", 0)
            duration = self._get_duration(tier)

            # Add the iptables rule
            success = self._add_iptables_rule(ip)
            if not success:
                return

            # Record the ban
            self._bans[ip] = {
                "banned_at": time.time(),
                "duration":  duration,
                "tier":      tier,
                "rate":      rate,
                "mean":      mean,
                "stddev":    stddev,
                "z_score":   z_score,
                "permanent": duration is None,
            }

        # Write audit log
        self._write_audit_ban(ip, rate, mean, z_score, duration)

        # Send Slack alert
        self.notifier.send_ban_alert(
            ip=ip,
            rate=rate,
            mean=mean,
            stddev=stddev,
            z_score=z_score,
            duration=duration
        )

        duration_str = f"{duration//60}min" if duration else "permanent"
        logger.warning(
            f"BANNED {ip} | rate={rate} mean={mean:.2f} "
            f"z={z_score:.2f} | duration={duration_str}"
        )

    def unban(self, ip: str):
        """
        Remove the iptables rule and update the ban record.
        Called by the Unbanner on schedule.
        """
        with self._lock:
            if ip not in self._bans:
                return

            ban_info = self._bans[ip]
            next_tier = ban_info["tier"] + 1

            # Remove iptables rule
            self._remove_iptables_rule(ip)

            # Remove from active bans
            del self._bans[ip]

        # Write audit log
        self._write_audit_unban(ip, next_tier)

        # Send Slack notification
        next_duration = self._get_duration(next_tier)
        self.notifier.send_unban_alert(ip=ip, next_tier=next_tier,
                                       next_duration=next_duration)

        logger.info(f"UNBANNED {ip} | next_tier={next_tier}")

        return next_tier

    def get_active_bans(self) -> dict:
        """Returns current ban state — used by the dashboard."""
        with self._lock:
            return dict(self._bans)

    def _get_duration(self, tier: int) -> int | None:
        """
        Returns ban duration in seconds for the given tier.
        Returns None for permanent ban (beyond last tier).

        Tier 0 → 10 min  (600s)
        Tier 1 → 30 min  (1800s)
        Tier 2 → 2 hours (7200s)
        Tier 3+ → permanent (None)
        """
        schedule = self.unban_schedule  # [10, 30, 120] in minutes
        if tier < len(schedule):
            return schedule[tier] * 60  # convert to seconds
        return None  # permanent

    def _add_iptables_rule(self, ip: str) -> bool:
        """
        Runs: iptables -I INPUT -s {ip} -j DROP
        -I inserts at the top so it's checked before any ACCEPT rules.
        Returns True on success, False on failure.
        """
        try:
            subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True,
                timeout=5  # never wait more than 5 seconds
            )
            logger.info(f"iptables rule added for {ip}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"iptables ban failed for {ip}: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"iptables error for {ip}: {e}")
            return False

    def _remove_iptables_rule(self, ip: str):
        """
        Runs: iptables -D INPUT -s {ip} -j DROP
        -D deletes the matching rule.
        """
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True,
                timeout=5
            )
            logger.info(f"iptables rule removed for {ip}")
        except Exception as e:
            logger.error(f"iptables unban failed for {ip}: {e}")

    def _write_audit_ban(self, ip: str, rate: float,
                         mean: float, z_score: float,
                         duration: int | None):
        """Write structured ban entry to audit log."""
        import os
        os.makedirs(
            os.path.dirname(self.audit_log_path), exist_ok=True
        )
        timestamp    = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        duration_str = f"{duration//60}min" if duration else "permanent"
        line = (
            f"[{timestamp}] BAN {ip} | "
            f"z-score={z_score:.2f} | "
            f"rate={rate} | "
            f"baseline={mean:.2f} | "
            f"duration={duration_str}\n"
        )
        with open(self.audit_log_path, "a") as f:
            f.write(line)

    def _write_audit_unban(self, ip: str, next_tier: int):
        """Write structured unban entry to audit log."""
        timestamp    = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        next_duration = self._get_duration(next_tier)
        next_str     = f"{next_duration//60}min" if next_duration else "permanent"
        line = (
            f"[{timestamp}] UNBAN {ip} | "
            f"condition=timer | "
            f"rate=- | "
            f"baseline=- | "
            f"next={next_str}\n"
        )
        with open(self.audit_log_path, "a") as f:
            f.write(line)
