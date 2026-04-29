import time
import threading
import logging
import psutil
from flask import Flask, jsonify, render_template_string

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
#  HTML template — the actual dashboard page                          #
# ------------------------------------------------------------------ #

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Server Guard — Live Dashboard</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'Courier New', monospace;
            background: #0d1117;
            color: #c9d1d9;
            padding: 20px;
        }

        h1 {
            color: #58a6ff;
            font-size: 1.6rem;
            margin-bottom: 4px;
        }

        .subtitle {
            color: #8b949e;
            font-size: 0.85rem;
            margin-bottom: 24px;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }

        .card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 16px;
        }

        .card h2 {
            font-size: 0.75rem;
            color: #8b949e;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 8px;
        }

        .card .value {
            font-size: 2rem;
            font-weight: bold;
            color: #f0f6fc;
        }

        .card .value.danger  { color: #f85149; }
        .card .value.warning { color: #d29922; }
        .card .value.ok      { color: #3fb950; }

        .card .unit {
            font-size: 0.8rem;
            color: #8b949e;
            margin-left: 4px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
        }

        th {
            text-align: left;
            padding: 8px 12px;
            color: #8b949e;
            border-bottom: 1px solid #30363d;
            font-weight: normal;
            text-transform: uppercase;
            font-size: 0.75rem;
        }

        td {
            padding: 8px 12px;
            border-bottom: 1px solid #21262d;
        }

        tr:last-child td { border-bottom: none; }

        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: bold;
        }

        .badge.banned   { background: #3d1111; color: #f85149; }
        .badge.active   { background: #0d2010; color: #3fb950; }
        .badge.warning  { background: #2d1f00; color: #d29922; }

        .uptime { color: #58a6ff; }

        #last-updated {
            color: #8b949e;
            font-size: 0.75rem;
            margin-top: 16px;
        }

        .section-title {
            color: #58a6ff;
            font-size: 1rem;
            margin: 24px 0 12px;
            border-bottom: 1px solid #30363d;
            padding-bottom: 8px;
        }
    </style>
</head>
<body>

<h1>🛡️ Server Guard</h1>
<p class="subtitle">Live anomaly detection dashboard — refreshes every 3 seconds</p>

<!-- Stat cards -->
<div class="grid" id="cards">
    <div class="card">
        <h2>Global Req/60s</h2>
        <div class="value" id="global-rate">—</div>
    </div>
    <div class="card">
        <h2>Baseline Mean</h2>
        <div class="value" id="mean">—</div>
        <div class="unit" id="stddev-label"></div>
    </div>
    <div class="card">
        <h2>Active Bans</h2>
        <div class="value" id="ban-count">—</div>
    </div>
    <div class="card">
        <h2>CPU Usage</h2>
        <div class="value" id="cpu">—</div>
    </div>
    <div class="card">
        <h2>Memory Usage</h2>
        <div class="value" id="memory">—</div>
    </div>
    <div class="card">
        <h2>Uptime</h2>
        <div class="value uptime" id="uptime">—</div>
    </div>
</div>

<!-- Banned IPs -->
<h3 class="section-title">🚫 Banned IPs</h3>
<div class="card">
    <table>
        <thead>
            <tr>
                <th>IP Address</th>
                <th>Rate</th>
                <th>Z-Score</th>
                <th>Duration</th>
                <th>Expires In</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody id="banned-table">
            <tr><td colspan="6" style="color:#8b949e">No active bans</td></tr>
        </tbody>
    </table>
</div>

<!-- Top IPs -->
<h3 class="section-title">📊 Top 10 Source IPs (last 60s)</h3>
<div class="card">
    <table>
        <thead>
            <tr>
                <th>IP Address</th>
                <th>Requests</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody id="top-ips-table">
            <tr><td colspan="3" style="color:#8b949e">No traffic yet</td></tr>
        </tbody>
    </table>
</div>

<p id="last-updated">Waiting for first update...</p>

<script>
    const START = Date.now();

    async function refresh() {
        try {
            const res  = await fetch('/metrics');
            const data = await res.json();

            // Stat cards
            const rate = data.global_rate;
            const el   = document.getElementById('global-rate');
            el.textContent = rate;
            el.className   = 'value ' + (rate > 100 ? 'danger' : rate > 30 ? 'warning' : 'ok');

            document.getElementById('mean').textContent = data.mean.toFixed(2);
            document.getElementById('stddev-label').textContent =
                'stddev: ' + data.stddev.toFixed(2);

            const bans   = document.getElementById('ban-count');
            bans.textContent = data.ban_count;
            bans.className   = 'value ' + (data.ban_count > 0 ? 'danger' : 'ok');

            document.getElementById('cpu').textContent    = data.cpu + '%';
            document.getElementById('memory').textContent = data.memory + '%';

            // Uptime
            const secs = Math.floor((Date.now() - START) / 1000);
            const h    = Math.floor(secs / 3600);
            const m    = Math.floor((secs % 3600) / 60);
            const s    = secs % 60;
            document.getElementById('uptime').textContent =
                `${h}h ${m}m ${s}s`;

            // Banned IPs table
            const banBody = document.getElementById('banned-table');
            if (data.banned_ips.length === 0) {
                banBody.innerHTML =
                    '<tr><td colspan="6" style="color:#8b949e">No active bans</td></tr>';
            } else {
                banBody.innerHTML = data.banned_ips.map(b => {
                    const expires = b.permanent ? '∞' :
                        Math.max(0, Math.round(b.expires_in)) + 's';
                    return `<tr>
                        <td><code>${b.ip}</code></td>
                        <td>${b.rate}</td>
                        <td>${b.z_score.toFixed(2)}</td>
                        <td>${b.duration}</td>
                        <td>${expires}</td>
                        <td><span class="badge banned">BANNED</span></td>
                    </tr>`;
                }).join('');
            }

            // Top IPs table
            const topBody = document.getElementById('top-ips-table');
            if (data.top_ips.length === 0) {
                topBody.innerHTML =
                    '<tr><td colspan="3" style="color:#8b949e">No traffic yet</td></tr>';
            } else {
                topBody.innerHTML = data.top_ips.map(([ip, count]) => {
                    const banned = data.banned_ips.some(b => b.ip === ip);
                    const badge  = banned
                        ? '<span class="badge banned">BANNED</span>'
                        : '<span class="badge active">ACTIVE</span>';
                    return `<tr>
                        <td><code>${ip}</code></td>
                        <td>${count}</td>
                        <td>${badge}</td>
                    </tr>`;
                }).join('');
            }

            document.getElementById('last-updated').textContent =
                'Last updated: ' + new Date().toLocaleTimeString();

        } catch(e) {
            console.error('Metrics fetch failed:', e);
        }
    }

    // Refresh every 3 seconds
    refresh();
    setInterval(refresh, 3000);
</script>
</body>
</html>
"""


class Dashboard:
    """
    Serves the live metrics dashboard on port 8080.
    Exposes a /metrics JSON endpoint that the frontend polls every 3s.
    """

    def __init__(self, config: dict, window, baseline, blocker):
        self.config   = config
        self.window   = window
        self.baseline = baseline
        self.blocker  = blocker
        self.port     = config["dashboard_port"]  # 8080
        self.start_time = time.time()

        self.app = Flask(__name__)
        self._register_routes()

    def _register_routes(self):

        @self.app.route("/")
        def index():
            return render_template_string(DASHBOARD_HTML)

        @self.app.route("/metrics")
        def metrics():
            return jsonify(self._collect_metrics())

    def _collect_metrics(self) -> dict:
        """Gather all metrics into one dict for the frontend."""
        mean, stddev = self.baseline.get_effective_baseline()
        active_bans  = self.blocker.get_active_bans()
        top_ips      = self.window.get_top_ips(10)
        now          = time.time()

        # Format banned IPs for the frontend
        banned_list = []
        for ip, info in active_bans.items():
            if info.get("permanent"):
                expires_in = -1
                duration_str = "Permanent"
            else:
                expires_in   = (info["banned_at"] + info["duration"]) - now
                duration_str = f"{info['duration'] // 60}min"

            banned_list.append({
                "ip":        ip,
                "rate":      info.get("rate", 0),
                "z_score":   info.get("z_score", 0),
                "duration":  duration_str,
                "expires_in": expires_in,
                "permanent": info.get("permanent", False),
            })

        return {
            "global_rate": self.window.get_global_rate(),
            "mean":        round(mean, 3),
            "stddev":      round(stddev, 3),
            "ban_count":   len(active_bans),
            "banned_ips":  banned_list,
            "top_ips":     top_ips,
            "cpu":         round(psutil.cpu_percent(), 1),
            "memory":      round(psutil.virtual_memory().percent, 1),
            "uptime":      round(now - self.start_time, 0),
        }

    def start(self):
        """Start Flask in a background thread."""
        thread = threading.Thread(
            target=lambda: self.app.run(
                host="0.0.0.0",
                port=self.port,
                debug=False,
                use_reloader=False
            ),
            daemon=True
        )
        thread.start()
        logger.info(f"Dashboard started on port {self.port}")
