#!/usr/bin/env python3
"""
Advanced Log Analyzer and Threat Detection System v2.1
Brute-force detection for SSH, Web (Nginx/Apache), and Windows logs,
risk scoring, GeoIP enrichment, and timeline visualization.

Authors: Muhammed Hüseyin Hanmoradi.

For educational use and authorized security analysis only.
"""

import re
import os
import sys
import time
import json
import argparse
from datetime import datetime, timedelta
from collections import defaultdict

# matplotlib is optional: required only when --plot is used
try:
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

# geoip2 is optional: only used when --geoip is specified with a .mmdb file
try:
    import geoip2.database
    HAS_GEOIP = True
except ImportError:
    HAS_GEOIP = False

# REGEX PATTERNS
PATTERNS = {
    "ssh": {
        "failed": re.compile(
            r"(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*Failed password for (invalid user )?(?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
        ),
        "accepted": re.compile(
            r"(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*Accepted password for (?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
        )
    },
    "web": {  # Nginx / Apache Combined Log Format
        "access": re.compile(
            r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+\[(?P<timestamp>[^\]]+)\]\s+\"(?P<method>\w+)\s+(?P<url>\S+)\s+[^\"]+\"\s+(?P<status>\d{3})"
        )
    },
    "windows": {  # Sample template for text-based exported EVTX records
        "failed": re.compile(
            r"(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*EventID:\s*4625.*User:\s*(?P<user>\w+).*IP:\s*(?P<ip>\d+\.\d+\.\d+\.\d+)"
        )
    }
}


class GeoIPLookup:
    """GeoIP enrichment module."""
    def __init__(self, db_path=None):
        self.reader = None
        if HAS_GEOIP and db_path and os.path.exists(db_path):
            try:
                self.reader = geoip2.database.Reader(db_path)
            except Exception as e:
                print(f"[!] GeoIP Database Failed to Load: {e}")
        elif db_path and not HAS_GEOIP:
            print("[!] geoip2 library is not installed. Install it with 'pip install geoip2' and try again.")

    def lookup(self, ip):
        if not self.reader:
            return {"country": "Unknown", "iso": "XX"}
        try:
            response = self.reader.city(ip)
            return {
                "country": response.country.name or "Unknown",
                "iso": response.country.iso_code or "XX"
            }
        except Exception:
            return {"country": "Unknown", "iso": "XX"}


class LogAnalyzerEngine:
    def __init__(self, log_type="ssh", geoip_db=None, window_minutes=5):
        self.log_type = log_type
        self.geoip = GeoIPLookup(geoip_db)
        self.window_minutes = window_minutes

        # ip -> { "failed_timestamps": [], "users": set(), "successful_logins": 0, "status_codes": defaultdict(int) }
        self.stats = defaultdict(lambda: {
            "failed_timestamps": [],
            "users": set(),
            "successful_logins": 0,
            "status_codes": defaultdict(int)
        })

    def parse_timestamp(self, ts_str):
        """
        Convert timestamp strings from various log formats to datetime objects.

        NOT: Each format is tested against its original ts_str; no pre-processing
        is performed. In the previous version, the Nginx timestamp's timezone (+0300)
        was stripped and then matched against a format expecting "%z", which
        always failed silently and fell back to datetime.now().
        """
        current_year = datetime.now().year
        formats = [
            ("%b %d %H:%M:%S", lambda dt: dt.replace(year=current_year)),  # SSH auth.log
            ("%d/%b/%Y:%H:%M:%S %z", lambda dt: dt),                        # Nginx/Apache
            ("%Y-%m-%d %H:%M:%S", lambda dt: dt)                            # Windows export
        ]

        for fmt, post_proc in formats:
            try:
                dt = datetime.strptime(ts_str, fmt)
                return post_proc(dt)
            except ValueError:
                continue
        return datetime.now()

    def process_line(self, line):
        """Process a single log line according to the selected type."""
        if self.log_type == "ssh":
            fail_match = PATTERNS["ssh"]["failed"].search(line)
            if fail_match:
                ip = fail_match.group("ip")
                user = fail_match.group("user")
                ts = self.parse_timestamp(fail_match.group("timestamp"))
                self.stats[ip]["failed_timestamps"].append(ts)
                self.stats[ip]["users"].add(user)
                return ("SSH_FAIL", ip, ts)

            success_match = PATTERNS["ssh"]["accepted"].search(line)
            if success_match:
                ip = success_match.group("ip")
                ts = self.parse_timestamp(success_match.group("timestamp"))
                self.stats[ip]["successful_logins"] += 1
                return ("SSH_SUCCESS", ip, ts)

        elif self.log_type == "web":
            match = PATTERNS["web"]["access"].search(line)
            if match:
                ip = match.group("ip")
                status = int(match.group("status"))
                ts = self.parse_timestamp(match.group("timestamp"))
                self.stats[ip]["status_codes"][status] += 1

                # HTTP 401/403 unauthorized attempts are accepted.
                # Many login forms (WordPress, Joomla, etc.) return an HTTP 200
                # even upon a failed login; this intuitive method is only
                # suitable for systems that return an authentication error at the HTTP level.
                if status in [401, 403]:
                    self.stats[ip]["failed_timestamps"].append(ts)
                    return ("WEB_UNAUTH", ip, ts)

        elif self.log_type == "windows":
            match = PATTERNS["windows"]["failed"].search(line)
            if match:
                ip = match.group("ip")
                user = match.group("user")
                ts = self.parse_timestamp(match.group("timestamp"))
                self.stats[ip]["failed_timestamps"].append(ts)
                self.stats[ip]["users"].add(user)
                return ("WIN_FAIL", ip, ts)

        return None

    def calculate_max_rate(self, timestamps):
        """Calculate the maximum failed attempt rate within a window period."""
        if not timestamps:
            return 0, 0

        sorted_ts = sorted(timestamps)
        max_count = 0
        window_delta = timedelta(minutes=self.window_minutes)

        for i, start_time in enumerate(sorted_ts):
            count = sum(1 for t in sorted_ts[i:] if t - start_time <= window_delta)
            if count > max_count:
                max_count = count

        total_time_min = max((sorted_ts[-1] - sorted_ts[0]).total_seconds() / 60.0, 1.0)
        overall_rate = len(timestamps) / total_time_min
        return max_count, round(overall_rate, 2)

    def calculate_risk_score(self, ip, data):
        """
        Risk Scoring Algorithm:
        - Number of failed attempts (volume)
        - Speed / density (high attempt count within window)
        - Targeted user diversity
        - Successful login exists? (breach risk)
        """
        score = 0
        failed_count = len(data["failed_timestamps"])
        unique_users = len(data["users"])
        success_logins = data["successful_logins"]
        max_window_attempts, _ = self.calculate_max_rate(data["failed_timestamps"])

        # 1. Volume Score
        score += min(failed_count * 2, 40)

        # 2. Speed / Density Score
        if max_window_attempts >= 10:
            score += 25
        elif max_window_attempts >= 5:
            score += 15

        # 3. Targeted User Diversity Score
        if unique_users > 3:
            score += 20
        elif unique_users > 1:
            score += 10

        # 4. Critical Success (Breach) Score
        if success_logins > 0 and failed_count > 0:
            score += 50

        return min(score, 100)

    def generate_report(self, threshold=5, min_risk_score=0):
        report = {
            "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "suspicious_activity": [],
            "summary": {"total_ips_scanned": len(self.stats)}
        }

        for ip, data in self.stats.items():
            failed_count = len(data["failed_timestamps"])
            if failed_count >= threshold:
                geo_info = self.geoip.lookup(ip)
                max_window_attempts, rate_per_min = self.calculate_max_rate(data["failed_timestamps"])
                risk_score = self.calculate_risk_score(ip, data)

                if risk_score >= min_risk_score:
                    report["suspicious_activity"].append({
                        "ip": ip,
                        "country": geo_info["country"],
                        "failed_attempts": failed_count,
                        "max_attempts_in_window": max_window_attempts,
                        "attempts_per_minute": rate_per_min,
                        "targeted_users": list(data["users"]),
                        "successful_logins": data["successful_logins"],
                        "risk_score": risk_score,
                        "breach_risk": data["successful_logins"] > 0 and failed_count > 0,
                        "timestamps": [ts.strftime("%Y-%m-%d %H:%M:%S") for ts in data["failed_timestamps"]]
                    })

        report["suspicious_activity"].sort(key=lambda x: x["risk_score"], reverse=True)
        return report


def plot_attack_timeline(report, output_file="attack_timeline.png"):
    """It visualizes the attack timeline using Matplotlib."""
    if not HAS_MATPLOTLIB:
        print("[!] matplotlib is not installed. To create a graph: pip install matplotlib")
        return

    events = []
    for entry in report["suspicious_activity"]:
        ip = entry["ip"]
        country = entry["country"]
        for ts_str in entry["timestamps"]:
            dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            events.append((dt, f"{ip} ({country})"))

    if not events:
        print("[-] No data was found to visualize.")
        return

    events.sort(key=lambda x: x[0])
    times = [e[0] for e in events]

    plt.figure(figsize=(12, 6))
    plt.hist(times, bins=20, color="crimson", edgecolor="black", alpha=0.7)
    plt.title("Attack Timeline and Density Distribution", fontsize=14, fontweight="bold")
    plt.xlabel("Time", fontsize=12)
    plt.ylabel("Number of Failed Attempts", fontsize=12)
    plt.grid(True, linestyle="--", alpha=0.5)
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(output_file)
    print(f"[+] The timeline chart has been saved: {output_file}")


def tail_f(file_path):
    """Generator function for live log monitoring."""
    file = open(file_path, "r", encoding="utf-8", errors="ignore")
    file.seek(0, os.SEEK_END)
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.5)
            continue
        yield line


def display_terminal_report(report):
    print(f"\n{'='*75}")
    print(f" Advanced Log and Threat Analysis Report - {report['analysis_time']}")
    print(f"{'='*75}")

    if not report["suspicious_activity"]:
        print("[+] No suspicious activity or threshold-exceeding IPs detected.")
        return

    for entry in report["suspicious_activity"]:
        status = "CRITICAL BREACH" if entry["breach_risk"] else ("HIGH RISK" if entry["risk_score"] > 60 else "SUSPICIOUS")
        print(f"[!] IP: {entry['ip']:<15} | Country: {entry['country']:<15} | Risk Score: {entry['risk_score']}/100 [{status}]")
        print(f"    Total Attempts: {entry['failed_attempts']} | Max Speed (5min window): {entry['max_attempts_in_window']} attempts")
        print(f"    Targeted Users: {', '.join(entry['targeted_users']) if entry['targeted_users'] else 'N/A'}")
        print(f"    Successful Logins: {entry['successful_logins']}")
        print("-" * 75)


def main():
    parser = argparse.ArgumentParser(description="Advanced Log Analyzer and Threat Detection System v2.1")
    parser.add_argument("logfile", help="Path to the log file to analyze")
    parser.add_argument("--type", dest="log_type", choices=["ssh", "web", "windows"], default="ssh",
                         help="Log format type (default: ssh)")
    parser.add_argument("-t", "--threshold", type=int, default=5, help="Failed attempt threshold (default: 5)")
    parser.add_argument("-r", "--min-risk", type=int, default=0, help="Minimum risk score filter (0-100)")
    parser.add_argument("--geoip", help="MaxMind GeoLite2-City/Country DB file path (.mmdb)")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--plot", action="store_true", help="Save attack timeline chart")
    parser.add_argument("--follow", action="store_true", help="Live monitoring mode (tail -f)")

    args = parser.parse_args()

    engine = LogAnalyzerEngine(log_type=args.log_type, geoip_db=args.geoip)

    if args.follow:
        if not os.path.exists(args.logfile):
            print(f"[!] Error: File not found: {args.logfile}")
            sys.exit(1)

        print(f"[*] Live monitoring started ({args.logfile}). New events are being analyzed...")
        try:
            for line in tail_f(args.logfile):
                result = engine.process_line(line)
                if result:
                    event_type, ip, ts = result
                    failed_len = len(engine.stats[ip]["failed_timestamps"])
                    if failed_len >= args.threshold:
                        geo = engine.geoip.lookup(ip)
                        print(f"[LIVE ALERT] [{ts}] IP: {ip} ({geo['country']}) - Event: {event_type} | Total Attempts: {failed_len}")
        except KeyboardInterrupt:
            print("\n[*] Live monitoring terminated.")
            return
        return

    # Static File Analysis
    if not os.path.exists(args.logfile):
        print(f"[!] Error: File not found: {args.logfile}")
        sys.exit(1)

    with open(args.logfile, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            engine.process_line(line)

    report = engine.generate_report(threshold=args.threshold, min_risk_score=args.min_risk)

    if args.json:
        print(json.dumps(report, indent=4, ensure_ascii=False))
    else:
        display_terminal_report(report)

    if args.plot:
        plot_attack_timeline(report)


if __name__ == "__main__":
    main()
