# Log Analyzer & Threat Detection Engine

A command-line tool that parses security logs (SSH, Nginx/Apache, or
Windows event exports) to detect brute-force login attempts. It aggregates
failed/successful logins per source IP, scores each IP's risk using a
weighted model (volume, attempt rate, target diversity, breach success),
optionally enriches results with GeoIP country data, and can plot an
attack timeline or tail a log file live.

## Features

- **Multi-format parsing**: SSH auth logs, Nginx/Apache combined log format, and Windows 4625 (failed logon) event exports
- **Time-aware brute-force detection**: tracks the maximum number of failed attempts inside a rolling time window (default 5 minutes), not just a raw total
- **Weighted risk scoring (0–100)**: combines attempt volume, attempt rate, number of distinct targeted usernames, and whether a successful login followed a failed streak
- **GeoIP enrichment** (optional): tags each suspicious IP with its country using a local MaxMind GeoLite2 database
- **Attack timeline visualization** (optional): saves a histogram of attempt activity over time as a PNG
- **Live monitoring mode** (`--follow`): tails a log file in real time and prints alerts as thresholds are crossed
- **JSON or human-readable report output**

## Installation

```bash
git clone https://github.com/<your-username>/log-analyzer.git
cd log-analyzer
pip install -r requirements.txt
```

Core SSH-log analysis works with **no third-party dependencies**. The
extras in `requirements.txt` are only needed if you use the matching flag:

| Dependency  | Needed for      |
|-------------|------------------|
| `matplotlib`| `--plot`         |
| `geoip2`    | `--geoip <file>` |

## Usage

```bash
# Basic SSH log analysis (default type, threshold 5)
python log_analyzer.py /var/log/auth.log

# Custom threshold and minimum risk score filter
python log_analyzer.py /var/log/auth.log -t 3 -r 40

# Nginx/Apache access log
python log_analyzer.py /var/log/nginx/access.log --type web -t 10

# Windows (pre-exported, see note below)
python log_analyzer.py winlogon_export.txt --type windows

# JSON output, for piping into other tools
python log_analyzer.py /var/log/auth.log --json

# GeoIP-enriched report (requires a GeoLite2-Country.mmdb file)
python log_analyzer.py /var/log/auth.log --geoip GeoLite2-Country.mmdb

# Save an attack timeline chart
python log_analyzer.py /var/log/auth.log --plot

# Live monitoring (like tail -f, with alerts)
python log_analyzer.py /var/log/auth.log --follow
```

A sample SSH log and a sample Nginx log are included so you can try the
tool immediately:

```bash
python log_analyzer.py sample_auth.log -t 3
python log_analyzer.py sample_nginx.log --type web -t 3
```

### Options

| Flag                | Description                                          | Default |
|---------------------|--------------------------------------------------------|---------|
| `logfile`           | Path to the log file to analyze                        | —       |
| `--type`            | Log format: `ssh`, `web`, or `windows`                  | `ssh`   |
| `-t`, `--threshold` | Failed-attempt threshold to flag an IP                  | `5`     |
| `-r`, `--min-risk`  | Minimum risk score (0–100) to include in the report     | `0`     |
| `--geoip`           | Path to a MaxMind GeoLite2 `.mmdb` file                 | none    |
| `--json`            | Output the report as JSON                               | off     |
| `--plot`            | Save an attack timeline PNG (`attack_timeline.png`)     | off     |
| `--follow`          | Live-tail the log file and print alerts as they happen  | off     |

## Example Output

```
===========================================================================
 Gelişmiş Log ve Tehdit Analiz Raporu - 2026-10-02 19:29:01
===========================================================================
[!] IP: 203.0.113.45    | Ülke: Bilinmiyor      | Risk Skoru: 87/100 [CRITICAL BREACH]
    Toplam Deneme: 6 | En Yüksek Hız (5dk pencereli): 6 deneme
    Hedef Kullanıcılar: root, admin, test
    Başarılı Oturum Açma: 1
---------------------------------------------------------------------------
```

JSON mode (`--json`) produces a structured report instead, suitable for
feeding into a SIEM, dashboard, or another script:

```json
{
    "ip": "203.0.113.45",
    "country": "Bilinmiyor",
    "failed_attempts": 6,
    "max_attempts_in_window": 6,
    "attempts_per_minute": 1.14,
    "targeted_users": ["root", "admin", "test"],
    "successful_logins": 1,
    "risk_score": 87,
    "breach_risk": true
}
```

## Known limitations

- **GeoIP** requires you to supply your own MaxMind GeoLite2 database file
  (free, requires a MaxMind account to download) — one is not bundled with
  this repo.
- **Windows support** does not parse raw binary `.evtx` files directly. It
  expects a text export where each failed-logon (Event ID 4625) line
  contains `EventID: 4625 ... User: <name> ... IP: <address>` on a single
  line. You'll need a small pre-processing step (e.g. `Get-WinEvent` piped
  through `Format-List` and reshaped, or a tool like `evtx_dump`) to get
  raw EVTX into that shape.
- **Web brute-force detection** currently flags only HTTP `401`/`403`
  responses as failed attempts. Many real-world login forms (WordPress,
  Joomla, custom apps) return HTTP `200` even on a failed login, with the
  failure indicated only in the page body — those attempts won't be
  caught by this heuristic. This tool is best suited to services that
  signal auth failure at the HTTP status level (reverse proxies with
  auth_request, basic auth, some APIs).
- Risk scoring weights are a simple heuristic, not a calibrated model —
  tune the thresholds in `calculate_risk_score()` to fit your environment.

## Disclaimer

This tool is intended **for educational purposes and authorized security
analysis only**. Only run it against log files you own or are authorized
to analyze. The author assumes no liability for any misuse of this
software.

## License

Released under the [MIT License](LICENSE).
