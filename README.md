# 🛡️ Server Guard — Anomaly Detection & DDoS Protection Engine

A real-time HTTP traffic monitoring daemon built for the HNG DevSecOps Stage 3 task.
Server Guard watches all incoming Nginx traffic, learns what normal looks like using
a rolling baseline, and automatically blocks anomalous IPs via iptables — all within
10 seconds of detection.

## Live URLs
- **Server IP:** 63.178.11.202
- **Metrics Dashboard:** http://63.178.11.202:8080
- **GitHub Repo:** https://github.com/maxr-eagle/server-guard

---

## Language Choice
**Python** — chosen for its readable syntax, powerful standard library
(collections.deque, threading, subprocess), and fast development
cycle. The statistical logic (mean, stddev) requires no external math
libraries, keeping the dependency footprint small.

---

## How the Sliding Window Works

Two deque structures track request rates over the last 60 seconds:
- One global deque (all traffic combined)
- One per-IP deque (one per source IP)

On every new request:
1. Append the current Unix timestamp to the right of the deque
2. Evict all timestamps older than 60 seconds from the left
3. len(deque) = current request rate

Eviction is O(1) — the deque is always time-ordered so only the
left side needs checking. Memory is bounded regardless of traffic
volume — even under 10,000 req/s, only 60 seconds of timestamps
are stored per IP.

---

## How the Baseline Works

- Window: 30-minute rolling window of per-second request counts
- Storage: deque(maxlen=1800) — one integer per second
- Recalculation: Every 60 seconds, computes mean and stddev
- Hourly slots: 24 per-hour accumulators for time-aware detection
- Floor: max(mean, 1.0) prevents division by zero on idle servers

---

## How Detection Works

An anomaly fires if either condition is true:
1. Z-score: (rate - mean) / stddev > 3.0
2. Rate multiplier: rate > 5 x mean

Error surge: If an IP's 4xx/5xx rate exceeds 3x the baseline
error rate, the z-score threshold tightens from 3.0 to 1.5.

Global anomaly: Slack alert only — no block possible.
Per-IP anomaly: iptables block + Slack alert within 10 seconds.

---

## How iptables Blocks an IP

iptables -I INPUT -s {ip} -j DROP

-I inserts the rule at position 1 — top of the INPUT chain —
checked before any ACCEPT rules. The kernel drops all packets
from the banned IP before they reach Nginx or Nextcloud.

Auto-unban backoff schedule:
- 1st offence: 10 minute ban
- 2nd offence: 30 minute ban
- 3rd offence: 2 hour ban
- 4th offence+: permanent ban

---

## Repository Structure

detector/
  main.py             — entry point, wires all components
  monitor.py          — tails and parses Nginx JSON logs
  monitor_window.py   — sliding window (deque-based)
  baseline.py         — rolling 30-min baseline, hourly slots
  detector.py         — z-score + rate anomaly detection
  blocker.py          — iptables ban management + audit log
  unbanner.py         — backoff unban schedule
  notifier.py         — Slack webhook alerts
  dashboard.py        — Flask live metrics dashboard
  config.yaml.example — config template (no secrets)
  requirements.txt
  Dockerfile
nginx/
  nginx.conf          — JSON access logs, real IP forwarding
docs/
  architecture.png
screenshots/
  Tool-running.png
  Ban-slack.png
  Unban-slack.png
  Global-alert-slack.png
  Iptables-banned.png
  Audit-log.png
  Baseline-graph.png
docker-compose.yml
README.md

---

## Setup Instructions

Prerequisites:
- Ubuntu 22.04 VPS (minimum 2 vCPU, 2 GB RAM)
- Ports 80 and 8080 open in firewall
- Docker and Docker Compose installed

Installation:

git clone https://github.com/maxr-eagle/server-guard
cd server-guard
cp detector/config.yaml.example detector/config.yaml
nano detector/config.yaml
docker compose up -d
docker compose ps
docker compose logs -f detector

Install Docker on fresh Ubuntu:
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker

---

## Slack Alerts

All alerts include: condition fired, current rate, baseline
mean/stddev, z-score, timestamp, and ban duration.

IP BANNED      — per-IP z-score or rate threshold exceeded
IP UNBANNED    — ban timer expired
GLOBAL ANOMALY — global rate anomalous (alert only)

---

## Dashboard

Live metrics at http://63.178.11.202:8080 — refreshes every 3 seconds:
- Global req/60s with colour coding
- Baseline mean and stddev
- Active bans with expiry timers
- Top 10 source IPs
- CPU and memory usage
- Daemon uptime

---

## Blog Post
https://medium.com/@grantmaxdev/how-i-built-a-ddos-detection-engine-from-scratch-71a9cbc42b91

---

## Screenshots

Tool-running.png        — daemon processing live log lines
Ban-slack.png           — Slack ban notification
Unban-slack.png         — Slack unban notification
Global-alert-slack.png  — Slack global anomaly alert
Iptables-banned.png     — iptables DROP rule for blocked IP
Audit-log.png           — structured audit log entries
Baseline-graph.png      — baseline recalculation over time
