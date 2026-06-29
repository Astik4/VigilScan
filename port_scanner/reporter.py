import json
import datetime
from jinja2 import Environment, select_autoescape
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.box import ASCII
from port_scanner.scoring import calculate_host_risk, get_cvss_severity, get_severity_color

METASPLOIT_MAP = {
    "CVE-2011-2523": "exploit/unix/ftp/vsftpd_234_backdoor",
    "CVE-2017-0144": "exploit/windows/smb/ms17_010_eternalblue",
    "CVE-2014-0160": "auxiliary/scanner/ssl/ssl_heartbleed",
    "CVE-2014-6271": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
    "CVE-2019-0708": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
    "CVE-2020-0796": "exploit/windows/smb/cve_2020_0796_smbghost",
    "CVE-2021-44228": "exploit/multi/http/log4j_rce_rc1",
    "CVE-2004-2687": "exploit/unix/misc/distcc_exec",
    "CVE-2010-2075": "exploit/unix/irc/unreal_ircd_3281_backdoor",
    "CVE-2007-2447": "exploit/multi/samba/usermap_script",
}

def get_exploit_suggestions(cve_id):
    """
    Returns a dict with exploit links and Metasploit module suggestions.
    """
    return {
        "github": f"https://github.com/search?q={cve_id}",
        "exploit_db": f"https://www.exploit-db.com/search?cve={cve_id}",
        "metasploit": METASPLOIT_MAP.get(cve_id, None)
    }

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VigilScan Security Audit Dashboard - {{ target_range }}</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-main: #0b0f19;
            --bg-card: #151d30;
            --bg-card-hover: #1c263f;
            --bg-active: #223150;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --border: #223150;
            
            /* Severity Colors */
            --color-critical: #ef4444;
            --color-high: #f97316;
            --color-medium: #eab308;
            --color-low: #10b981;
            --color-info: #3b82f6;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg-main);
            color: var(--text-main);
            line-height: 1.5;
            padding: 2rem;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 2rem;
            border-bottom: 1px solid var(--border);
            margin-bottom: 2rem;
        }

        .header-title h1 {
            font-size: 2.2rem;
            font-weight: 700;
            letter-spacing: -0.025em;
            background: linear-gradient(to right, #60a5fa, #a78bfa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .header-title p {
            color: var(--text-muted);
            margin-top: 0.25rem;
        }

        .timestamp {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            color: var(--text-muted);
            background: #111827;
            padding: 0.5rem 1rem;
            border-radius: 8px;
            border: 1px solid var(--border);
        }

        /* Dashboard Summary Grid */
        .summary-grid {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr 1fr;
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        @media (max-width: 768px) {
            .summary-grid {
                grid-template-columns: 1fr;
            }
        }

        .card {
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.5rem;
            transition: all 0.3s ease;
        }

        .card:hover {
            transform: translateY(-2px);
            border-color: #3b82f680;
        }

        .stat-card {
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }

        .stat-label {
            color: var(--text-muted);
            font-size: 0.9rem;
            font-weight: 500;
        }

        .stat-value {
            font-size: 2.2rem;
            font-weight: 700;
            line-height: 1.2;
            margin-top: 0.5rem;
        }

        /* Split Screen Layout */
        .split-layout {
            display: grid;
            grid-template-columns: 350px 1fr;
            gap: 2rem;
            align-items: start;
        }

        @media (max-width: 992px) {
            .split-layout {
                grid-template-columns: 1fr;
            }
        }

        /* Left Side Host List */
        .host-list {
            display: flex;
            flex-direction: column;
            gap: 1rem;
            max-height: 800px;
            overflow-y: auto;
            padding-right: 0.5rem;
        }

        .host-card {
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 1.25rem;
            cursor: pointer;
            transition: all 0.2s ease;
            position: relative;
        }

        .host-card:hover {
            background-color: var(--bg-card-hover);
        }

        .host-card.active {
            background-color: var(--bg-active);
            border-color: #3b82f6;
            box-shadow: 0 0 10px rgba(59, 130, 246, 0.2);
        }

        .host-card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }

        .host-ip {
            font-weight: 700;
            font-size: 1.1rem;
        }

        .host-target {
            font-size: 0.85rem;
            color: var(--text-muted);
            word-break: break-all;
        }

        .badge {
            display: inline-block;
            padding: 0.2rem 0.5rem;
            border-radius: 6px;
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.025em;
        }

        .badge-confirmed { background-color: rgba(16, 185, 129, 0.15); color: var(--color-low); border: 1px solid rgba(16, 185, 129, 0.3); }
        .badge-assumed { background-color: rgba(245, 158, 11, 0.15); color: var(--color-medium); border: 1px solid rgba(245, 158, 11, 0.3); }
        
        .badge-critical { background-color: rgba(239, 68, 68, 0.2); color: var(--color-critical); border: 1px solid rgba(239, 68, 68, 0.4); }
        .badge-high { background-color: rgba(249, 115, 22, 0.2); color: var(--color-high); border: 1px solid rgba(249, 115, 22, 0.4); }
        .badge-medium { background-color: rgba(234, 179, 8, 0.2); color: var(--color-medium); border: 1px solid rgba(234, 179, 8, 0.4); }
        .badge-low { background-color: rgba(16, 185, 129, 0.2); color: var(--color-low); border: 1px solid rgba(16, 185, 129, 0.4); }
        .badge-info { background-color: rgba(59, 130, 246, 0.2); color: var(--color-info); border: 1px solid rgba(59, 130, 246, 0.4); }

        .host-summary-stats {
            display: flex;
            gap: 1rem;
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-top: 0.5rem;
        }

        /* Right Side Host Detail Panel */
        .detail-panel {
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 2rem;
            min-height: 500px;
        }

        .host-details-section {
            display: none;
        }

        .host-details-section.active {
            display: block;
        }

        .detail-header {
            margin-bottom: 1.5rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }

        .detail-title h2 {
            font-size: 1.6rem;
            font-weight: 700;
        }

        .detail-title p {
            color: var(--text-muted);
            font-size: 0.9rem;
        }

        /* Risk Gauge Row */
        .risk-row {
            display: flex;
            align-items: center;
            gap: 2rem;
            margin-bottom: 2rem;
            background: rgba(0,0,0,0.15);
            padding: 1.25rem 2rem;
            border-radius: 10px;
            border: 1px solid var(--border);
        }

        .risk-gauge {
            width: 70px;
            height: 70px;
            border-radius: 50%;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            font-weight: 700;
            border: 5px solid;
        }

        .gauge-score {
            font-size: 1.4rem;
            line-height: 1;
        }

        .gauge-label {
            font-size: 0.6rem;
            text-transform: uppercase;
        }

        .risk-summary-text h4 {
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 0.2rem;
        }

        .risk-summary-text p {
            font-size: 0.85rem;
            color: var(--text-muted);
        }

        /* Table CSS */
        .table-container {
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 2rem;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }

        th {
            background-color: #0f1626;
            color: var(--text-main);
            font-weight: 600;
            font-size: 0.85rem;
            padding: 0.75rem 1.25rem;
            border-bottom: 1px solid var(--border);
        }

        td {
            padding: 1rem 1.25rem;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
            font-size: 0.9rem;
        }

        tr:last-child td {
            border-bottom: none;
        }

        .port-col {
            font-family: 'JetBrains Mono', monospace;
            font-weight: 600;
        }

        .service-name {
            font-weight: 600;
        }

        .version-text {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            color: var(--text-muted);
        }

        .banner-text {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            color: #8892b0;
            background: #0b111e;
            padding: 0.3rem 0.5rem;
            border-radius: 5px;
            margin-top: 0.4rem;
            word-break: break-all;
            display: block;
        }

        /* Web App Profile CSS */
        .web-app-profile {
            margin-top: 0.6rem;
            padding: 0.6rem;
            background: #0d1322;
            border: 1px solid #1e293b;
            border-radius: 6px;
            font-size: 0.8rem;
        }

        .web-app-title {
            font-weight: 500;
            color: #f3f4f6;
            margin-bottom: 0.25rem;
        }

        .web-app-title span {
            color: #9ca3af;
            font-weight: normal;
        }

        .web-app-techs {
            display: flex;
            flex-wrap: wrap;
            gap: 0.35rem;
            margin-top: 0.4rem;
        }

        .tech-pill {
            display: inline-block;
            padding: 0.1rem 0.4rem;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 600;
            background: #1e293b;
            color: #60a5fa;
            border: 1px solid rgba(96, 165, 250, 0.2);
        }

        .web-app-ssl {
            margin-top: 0.5rem;
            padding-top: 0.5rem;
            border-top: 1px dashed #1e293b;
            font-size: 0.75rem;
            color: #9ca3af;
        }

        .web-app-ssl strong {
            color: #f3f4f6;
        }

        /* CVE cards */
        .cve-item {
            background: #0f172a;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 0.75rem 1rem;
            margin-bottom: 0.5rem;
        }

        .cve-item:last-child {
            margin-bottom: 0;
        }

        .cve-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-weight: 600;
            font-size: 0.85rem;
            margin-bottom: 0.25rem;
        }

        .cve-id {
            font-family: 'JetBrains Mono', monospace;
            color: #60a5fa;
            text-decoration: none;
        }

        .cve-id:hover {
            text-decoration: underline;
        }

        .cve-desc {
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-top: 0.25rem;
        }

        .exploit-links {
            margin-top: 0.5rem;
            padding-top: 0.5rem;
            border-top: 1px dashed var(--border);
            display: flex;
            flex-wrap: wrap;
            gap: 1rem;
            font-size: 0.75rem;
        }

        .exploit-links code {
            font-family: 'JetBrains Mono', monospace;
            background: rgba(239, 68, 68, 0.1);
            color: #ef4444;
            padding: 0.1rem 0.3rem;
            border-radius: 4px;
        }

        /* Formula Box */
        .formula-box {
            background: linear-gradient(135deg, #101726 0%, #1e293b 100%);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.25rem;
            font-size: 0.85rem;
            margin-top: 2rem;
        }

        .formula-title {
            font-weight: 600;
            margin-bottom: 0.5rem;
            color: #a78bfa;
        }

        .formula-math {
            font-family: 'JetBrains Mono', monospace;
            background: rgba(0,0,0,0.2);
            padding: 0.5rem 0.75rem;
            border-radius: 6px;
            margin-bottom: 0.75rem;
            border-left: 3px solid #a78bfa;
        }

        .formula-details ul {
            list-style: none;
            padding-left: 0.5rem;
        }

        .formula-details li {
            margin-bottom: 0.4rem;
            color: var(--text-muted);
        }

        .formula-details li:last-child {
            margin-bottom: 0;
        }

        footer {
            text-align: center;
            padding: 3rem 0 1rem;
            color: var(--text-muted);
            font-size: 0.85rem;
            border-top: 1px solid var(--border);
            margin-top: 4rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-title">
                <h1>VigilScan Security Dashboard</h1>
                <p>Security Audit Report for range: <strong>{{ target_range }}</strong></p>
            </div>
            <div class="timestamp">
                Report generated: {{ scan_time }}
            </div>
        </header>

        <!-- Summary Grid -->
        <div class="summary-grid">
            <div class="card stat-card">
                <span class="stat-label">Hosts Scanned</span>
                <span class="stat-value" style="color: #3b82f6;">{{ stats.total_scanned }}</span>
            </div>
            <div class="card stat-card">
                <span class="stat-label">Alive Hosts</span>
                <span class="stat-value" style="color: #10b981;">{{ stats.alive_count }}</span>
            </div>
            <div class="card stat-card">
                <span class="stat-label">Vulnerable Hosts</span>
                <span class="stat-value" style="color: #fb923c;">{{ stats.vulnerable_hosts }}</span>
            </div>
            <div class="card stat-card">
                <span class="stat-label">Average Risk Score</span>
                <span class="stat-value" style="color: #a78bfa;">{{ stats.average_risk|round(1) }}/10.0</span>
            </div>
        </div>

        <!-- Split Layout -->
        <div class="split-layout">
            
            <!-- Left Panel: Host List -->
            <div class="host-list">
                {% for h in hosts %}
                <div id="card-{{ h.ip|replace('.', '-') }}" class="host-card {% if loop.first %}active{% endif %}" onclick="selectHost('{{ h.ip|replace('.', '-') }}')">
                    <div class="host-card-header">
                        <span class="host-ip">{{ h.ip }}</span>
                        <span class="badge badge-{{ h.host_severity|lower }}">{{ h.host_severity }}</span>
                    </div>
                    <div class="host-target">{{ h.target or '' }}</div>
                    <div class="host-summary-stats">
                        <span>Score: <strong>{{ h.host_risk_score }}</strong></span>
                        <span>Ports: <strong>{{ h.findings|length }}</strong></span>
                        <span>Vulnerabilities: <strong>{{ h.stats.vulnerable }}</strong></span>
                    </div>
                </div>
                {% endfor %}
            </div>

            <!-- Right Panel: Host Details -->
            <div class="detail-panel">
                {% for h in hosts %}
                <div id="details-{{ h.ip|replace('.', '-') }}" class="host-details-section {% if loop.first %}active{% endif %}">
                    
                    <div class="detail-header">
                        <div class="detail-title">
                            <h2>{{ h.ip }}</h2>
                            <p>Hostname: {{ h.target or 'Unknown' }} | Audit time: {{ h.scan_time }}</p>
                        </div>
                        <span class="badge badge-{{ h.host_severity|lower }}">{{ h.host_severity }} Severity</span>
                    </div>

                    <div class="risk-row">
                        <div class="risk-gauge" style="border-color: {{ h.risk_color_hex }}; color: {{ h.risk_color_hex }};">
                            <span class="gauge-score">{{ h.host_risk_score }}</span>
                            <span class="gauge-label">Score</span>
                        </div>
                        <div class="risk-summary-text">
                            <h4>Overall Host Risk Level: <span style="color: {{ h.risk_color_hex }};">{{ h.host_severity }}</span></h4>
                            <p>This risk score aggregates the severity of the highest vulnerability found, compounding vulnerability factors, and the host's overall attack surface exposure.</p>
                        </div>
                    </div>

                    <!-- Findings Table -->
                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th style="width: 15%">Port</th>
                                    <th style="width: 25%">Service details</th>
                                    <th style="width: 15%">State</th>
                                    <th style="width: 45%">Matched CVEs & Exploit Suggestions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for f in h.findings if not show_only_open or f.state not in ['Closed', 'Filtered'] %}
                                <tr>
                                    <td class="port-col">{{ f.port }}/TCP</td>
                                    <td>
                                        <div class="service-name">{{ f.service }}</div>
                                        <div class="version-text">Version: {{ f.version or 'Not detected' }}</div>
                                        {% if f.banner %}
                                        <code class="banner-text" title="Raw Banner String">{{ f.banner }}</code>
                                        {% endif %}
                                        {% if f.http_profile %}
                                        <div class="web-app-profile">
                                            <div class="web-app-title">🌐 Web App Profile: <span>{{ f.http_profile.title }}</span></div>
                                            {% if f.http_profile.techs %}
                                            <div class="web-app-techs">
                                                {% for tech in f.http_profile.techs %}
                                                <span class="tech-pill">{{ tech }}</span>
                                                {% endfor %}
                                            </div>
                                            {% endif %}
                                            {% if f.http_profile.ssl %}
                                            <div class="web-app-ssl">
                                                🔒 <strong>SSL Cert:</strong> CN={{ f.http_profile.ssl.subject }}<br>
                                                &nbsp;&nbsp;&nbsp;&nbsp;Issuer: CN={{ f.http_profile.ssl.issuer }}<br>
                                                &nbsp;&nbsp;&nbsp;&nbsp;Expires: {{ f.http_profile.ssl.not_after }}
                                            </div>
                                            {% endif %}
                                        </div>
                                        {% endif %}
                                    </td>
                                    <td>
                                        {% if f.state == 'Closed' %}
                                        <span class="badge badge-critical" style="background-color: rgba(239, 68, 68, 0.15); color: var(--color-critical); border: 1px solid rgba(239, 68, 68, 0.3);">Closed</span>
                                        {% elif f.state == 'Filtered' %}
                                        <span class="badge badge-medium" style="background-color: rgba(245, 158, 11, 0.15); color: var(--color-medium); border: 1px solid rgba(245, 158, 11, 0.3);">Filtered</span>
                                        {% elif f.confirmed %}
                                        <span class="badge badge-confirmed">Confirmed</span>
                                        {% else %}
                                        <span class="badge badge-confirmed">Open</span>
                                        {% endif %}
                                    </td>
                                    <td>
                                        {% if f.cves %}
                                            {% for cve in f.cves[:3] %}
                                            <div class="cve-item">
                                                <div class="cve-header">
                                                    <a href="https://nvd.nist.gov/vuln/detail/{{ cve.id }}" target="_blank" class="cve-id">{{ cve.id }}</a>
                                                    {% set cve_sev = get_cvss_severity(cve.score) %}
                                                    <span class="badge badge-{{ cve_sev|lower }}">{{ cve_sev }} ({{ cve.score }})</span>
                                                </div>
                                                <div class="cve-desc">{{ cve.description }}</div>
                                                
                                                <!-- Exploit Suggester links -->
                                                <div class="exploit-links">
                                                    {% set exploit_sug = get_exploit_suggestions(cve.id) %}
                                                    {% if exploit_sug.metasploit %}
                                                    <span style="color: #ef4444; font-weight: 500; display: flex; align-items: center; gap: 0.2rem;">
                                                        🛡️ MSF: <code>{{ exploit_sug.metasploit }}</code>
                                                    </span>
                                                    {% endif %}
                                                    <a href="{{ exploit_sug.github }}" target="_blank" style="color: #60a5fa; text-decoration: none;">🔍 GitHub PoC</a>
                                                    <a href="{{ exploit_sug.exploit_db }}" target="_blank" style="color: #60a5fa; text-decoration: none;">🔍 Exploit-DB</a>
                                                </div>
                                            </div>
                                            {% endfor %}
                                            {% if f.cves|length > 3 %}
                                            <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.5rem; text-align: right;">
                                                ... and {{ f.cves|length - 3 }} more CVEs matched
                                            </div>
                                            {% endif %}
                                        {% else %}
                                            <div style="color: var(--text-muted); font-size: 0.9rem; font-style: italic;">
                                                {% if f.version %}
                                                No vulnerabilities found on NVD database for this software version.
                                                {% else %}
                                                CVE search skipped. No service version could be determined.
                                                {% endif %}
                                            </div>
                                        {% endif %}
                                    </td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>

                    <!-- Risk Calculator breakdown -->
                    <div class="formula-box">
                        <div class="formula-title">Host Risk Scoring Model Breakdown</div>
                        <div class="formula-math">
                            Host Risk Score (R) = Min(10.0, S_max + 0.1 * &Sigma;(S_i) + Min(1.0, 0.05 * N_clean))
                        </div>
                        <div class="formula-details">
                            <ul>
                                <li>
                                    <strong>S_max (Baseline Severity):</strong> {{ h.host_risk_details.s_max }} — Highest CVSS score found.
                                </li>
                                <li>
                                    <strong>&Sigma;(S_i) (Compounding Vulnerabilities):</strong> {{ h.host_risk_details.s_others_sum }} — Remaining CVSS scores sum (weight: 10%).
                                </li>
                                <li>
                                    <strong>N_clean (Attack Surface Penalty):</strong> {{ h.host_risk_details.clean_ports }} clean ports (Penalty: +{{ h.host_risk_details.attack_surface_penalty }}) — Exposed open ports.
                                </li>
                            </ul>
                        </div>
                    </div>

                </div>
                {% endfor %}
            </div>

        </div>

        <footer>
            VigilScan CLI • Security Audit Dashboard
        </footer>
    </div>

    <!-- JavaScript to toggle host details views -->
    <script>
        function selectHost(hostId) {
            // Hide all host details sections
            var details = document.getElementsByClassName('host-details-section');
            for (var i = 0; i < details.length; i++) {
                details[i].classList.remove('active');
            }
            // Remove active class from all host cards
            var cards = document.getElementsByClassName('host-card');
            for (var i = 0; i < cards.length; i++) {
                cards[i].classList.remove('active');
            }
            // Show selected host details
            document.getElementById('details-' + hostId).classList.add('active');
            // Add active class to selected card
            document.getElementById('card-' + hostId).classList.add('active');
        }
    </script>
</body>
</html>
"""

def print_cli_report(target, ip, elapsed_seconds, findings, console, os_info=None, show_only_open=False):
    """
    Renders the scan findings to the CLI using Rich table formatting.
    """
    host_risk_score, host_severity = calculate_host_risk(findings)
    color_info = get_severity_color(host_severity)
    rich_color = color_info["rich"]
    
    # 1. Print Summary Header
    header_text = f"[bold white]SCAN REPORT FOR {target} ({ip})[/bold white]\n"
    if os_info:
        header_text += f"[cyan]OS Details: {os_info}[/cyan]\n"
    header_text += f"[dim]Duration: {elapsed_seconds:.2f} seconds | Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]"
    
    console.print()
    console.print(Panel(
        Align.center(header_text),
        box=ASCII,
        border_style="blue"
    ))
    console.print()
    
    # 2. Create findings table
    table = Table(
        title="Audit Findings (Open Ports & Detected Services)",
        title_style="bold blue",
        header_style="bold cyan",
        box=ASCII
    )
    
    table.add_column("Port/Proto", style="bold green", no_wrap=True)
    table.add_column("Service", style="bold white", no_wrap=True)
    table.add_column("Version", style="dim", no_wrap=True)
    table.add_column("State", no_wrap=True)
    table.add_column("Top CVE & Suggestions", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("CVSS", justify="right", no_wrap=True)
    
    stats_vulnerable = 0
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    
    # Filter display findings if show_only_open is active
    display_findings = findings
    if show_only_open:
        display_findings = [f for f in findings if f.get("state") not in ("Closed", "Filtered")]
        
    closed_ports_count = sum(1 for f in display_findings if f.get("state") == "Closed")
    show_closed_in_table = closed_ports_count <= 10 or show_only_open
    
    filtered_ports_count = sum(1 for f in display_findings if f.get("state") == "Filtered")
    show_filtered_in_table = filtered_ports_count <= 10 or show_only_open
    
    for f in display_findings:
        port_str = f"{f['port']}/TCP"
        service = f['service']
        version = f['version'] or "-"
        state = f.get("state") or ("Confirmed" if f['confirmed'] else "Open")
        
        if state == "Closed" and not show_closed_in_table:
            continue
        if state == "Filtered" and not show_filtered_in_table:
            continue
            
        cves = f.get("cves", [])
        if cves:
            stats_vulnerable += 1
            top_cve = cves[0]
            top_cve_id = top_cve["id"]
            top_cve_score = top_cve["score"]
            top_cve_sev = get_cvss_severity(top_cve_score)
            
            # Count severities
            for cve in cves:
                sev = get_cvss_severity(cve["score"])
                severity_counts[sev] += 1
                
            cve_color = get_severity_color(top_cve_sev)["rich"]
            
            # Exploit Suggester Integration for top CVE
            exploit_sug = get_exploit_suggestions(top_cve_id)
            msf_module = exploit_sug["metasploit"]
            
            top_cve_display = f"[bold]{top_cve_id}[/bold]"
            if msf_module:
                top_cve_display += f"\n[dim red]MSF: {msf_module}[/dim red]"
            else:
                top_cve_display += f"\n[dim cyan]PoC: Github/EDB[/dim cyan]"
                
            severity_display = f"[{cve_color}]{top_cve_sev}[/{cve_color}]"
            cvss_display = f"[{cve_color}]{top_cve_score:.1f}[/{cve_color}]"
        else:
            top_cve_display = "-"
            severity_display = "[blue]Info[/blue]"
            cvss_display = "0.0"
            if state in ("Confirmed", "Open"):
                severity_counts["Info"] += 1
            
        if state == "Confirmed":
            state_display = "[green]Confirmed[/green]"
        elif state == "Open":
            state_display = "[green]Open[/green]"
        elif state == "Closed":
            state_display = "[red]Closed[/red]"
        elif state == "Filtered":
            state_display = "[yellow]Filtered[/yellow]"
        else:
            state_display = f"[white]{state}[/white]"
        
        table.add_row(
            port_str,
            service,
            version,
            state_display,
            top_cve_display,
            severity_display,
            cvss_display
        )
        
        http_profile = f.get("http_profile")
        if http_profile:
            lines = []
            if http_profile.get("title") and http_profile["title"] != "Unknown":
                lines.append(f"|_ [bold]Title:[/bold] {http_profile['title']}")
            if http_profile.get("server"):
                lines.append(f"|_ [bold]Server:[/bold] {http_profile['server']}")
            if http_profile.get("techs"):
                lines.append(f"|_ [bold]Techs:[/bold] {', '.join(http_profile['techs'])}")
            if http_profile.get("ssl"):
                ssl_info = http_profile["ssl"]
                lines.append(f"|_ [bold]SSL Cert:[/bold] CN={ssl_info['subject']} (Issuer: CN={ssl_info['issuer']})")
                
            if lines:
                profile_text = Text.from_markup("\n".join(f"[dim cyan]{l}[/dim cyan]" for l in lines))
                table.add_row(
                    "",
                    "",
                    "",
                    "",
                    profile_text,
                    "",
                    ""
                )
        
    console.print(table)
    if not show_closed_in_table:
        console.print(f"  [dim]* Not showing {closed_ports_count} closed ports in the table. (Use -oA to generate a full HTML report)[/dim]")
    if not show_filtered_in_table:
        console.print(f"  [dim]* Not showing {filtered_ports_count} filtered ports in the table. (Use -oA to generate a full HTML report)[/dim]")
    console.print()
    
    # 3. Print Overall Risk Summary Card
    cve_stats_text = (
        f"[bold red]Critical: {severity_counts['Critical']}[/bold red]  |  "
        f"[orange1]High: {severity_counts['High']}[/orange1]  |  "
        f"[yellow]Medium: {severity_counts['Medium']}[/yellow]  |  "
        f"[green]Low: {severity_counts['Low']}[/green]  |  "
        f"[blue]Info: {severity_counts['Info']}[/blue]"
    )
    
    risk_bar_length = int(host_risk_score * 2) # scaling score to a 20-character bar
    risk_bar = f"[{rich_color}]" + "#" * risk_bar_length + "-" * (20 - risk_bar_length) + f"[/{rich_color}]"
    
    panel_content = Text()
    panel_content.append("Vulnerability Distribution:\n", style="bold")
    panel_content.append(Text.from_markup(f"{cve_stats_text}\n\n"))
    panel_content.append("Host Risk Meter:\n", style="bold")
    panel_content.append(Text.from_markup(f"{risk_bar}  [bold]{host_risk_score}/10.0[/bold] ([{rich_color}]{host_severity}[/{rich_color}])\n\n"))
    panel_content.append("Risk Scoring Breakdown:\n", style="bold magenta")
    
    # Show breakdown details
    port_max_scores = []
    clean_ports = 0
    for f in findings:
        state = f.get("state", "Open")
        if state in ("Closed", "Filtered"):
            continue
        cves = f.get("cves", [])
        if cves:
            port_max_scores.append(max(c["score"] for c in cves))
        else:
            clean_ports += 1
            
    s_max = max(port_max_scores) if port_max_scores else 0.0
    s_others = sorted(port_max_scores, reverse=True)[1:] if len(port_max_scores) > 1 else []
    s_others_sum = sum(s_others)
    compounding_factor = 0.1 * s_others_sum
    attack_surface_penalty = min(1.0, 0.05 * clean_ports)
    
    panel_content.append(f"  - Baseline Severity (S_max): {s_max:.1f}\n", style="dim")
    panel_content.append(f"  - Compounding Vulnerability Factor (0.1 * {s_others_sum:.1f}): +{compounding_factor:.2f}\n", style="dim")
    panel_content.append(f"  - Attack Surface Penalty (0.05 * {clean_ports} clean ports): +{attack_surface_penalty:.2f}\n", style="dim")
    panel_content.append(f"  - Overall Host Risk Score: min(10.0, {s_max:.1f} + {compounding_factor:.2f} + {attack_surface_penalty:.2f}) = ", style="dim")
    panel_content.append(f"{host_risk_score}", style=f"bold {rich_color}")
    
    console.print(Panel(
        panel_content,
        title="[bold white]Overall Host Risk Assessment[/bold white]",
        border_style=rich_color,
        box=ASCII
    ))
    console.print()

def export_json_report(filepath, target_range, hosts_results, elapsed_seconds, show_only_open=False):
    """
    Exports full multi-host audit scan details to a JSON file.
    """
    import copy
    results_copy = copy.deepcopy(hosts_results)
    if show_only_open:
        for host in results_copy:
            if "findings" in host:
                host["findings"] = [f for f in host["findings"] if f.get("state") not in ("Closed", "Filtered")]
                
    alive_hosts = [h for h in results_copy if h.get("findings")]
    vulnerable_hosts = sum(1 for h in results_copy if h.get("stats", {}).get("vulnerable", 0) > 0)
    
    report_data = {
        "target_range": target_range,
        "scan_time": datetime.datetime.now().isoformat(),
        "total_elapsed_seconds": round(elapsed_seconds, 2),
        "stats": {
            "total_scanned": len(results_copy),
            "alive_count": len(alive_hosts),
            "vulnerable_hosts": vulnerable_hosts
        },
        "hosts": results_copy
    }
    
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4)

def export_html_report(filepath, target_range, hosts_results, elapsed_seconds, show_only_open=False):
    """
    Generates a beautiful offline multi-host HTML report dashboard.
    """
    import copy
    results_copy = copy.deepcopy(hosts_results)
    
    alive_hosts = [h for h in results_copy if h.get("findings")]
    vulnerable_hosts = sum(1 for h in results_copy if h.get("stats", {}).get("vulnerable", 0) > 0)
    
    average_risk = 0.0
    if alive_hosts:
        average_risk = sum(h["host_risk_score"] for h in alive_hosts) / len(alive_hosts)
        
    stats = {
        "total_scanned": len(results_copy),
        "alive_count": len(alive_hosts),
        "vulnerable_hosts": vulnerable_hosts,
        "average_risk": average_risk
    }
    
    env = Environment(autoescape=select_autoescape(['html', 'xml']))
    template = env.from_string(HTML_TEMPLATE)
    html_output = template.render(
        target_range=target_range,
        scan_time=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        elapsed_seconds=round(elapsed_seconds, 2),
        stats=stats,
        hosts=results_copy,
        show_only_open=show_only_open,
        get_cvss_severity=get_cvss_severity,
        get_exploit_suggestions=get_exploit_suggestions
    )
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_output)
