"""
AI-Powered Cyber Defense — Educational Prototype
This project analyzes SYNTHETIC sample security logs only.
It uses transparent rule-based indicators; it is not a trained AI model
and it does not monitor real devices or networks.
Run: python cyber_defense.py
"""
import csv
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

DATA_FILE = Path(__file__).with_name("sample_logs.csv")

def load_logs(path=DATA_FILE):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

def analyze_logs(rows):
    failed_by_ip = Counter()
    events_by_ip = defaultdict(list)
    alerts = []
    for row in rows:
        ip = row.get("source_ip", "unknown")
        event = row.get("event_type", "").lower()
        events_by_ip[ip].append(row)
        if event == "failed_login":
            failed_by_ip[ip] += 1

    for ip, count in failed_by_ip.items():
        if count >= 3:
            alerts.append({
                "severity": "HIGH",
                "source_ip": ip,
                "reason": f"{count} failed login attempts in sample data",
                "recommendation": "Review the account activity and apply normal account-security procedures."
            })

    for ip, events in events_by_ip.items():
        for row in events:
            event = row.get("event_type", "").lower()
            if event in {"malware_detected", "suspicious_process"}:
                alerts.append({
                    "severity": "HIGH" if event == "malware_detected" else "MEDIUM",
                    "source_ip": ip,
                    "reason": f"Sample event marked {event}",
                    "recommendation": "Verify the alert with an authorized security analyst."
                })
            hour = None
            try:
                hour = datetime.fromisoformat(row["timestamp"]).hour
            except (ValueError, KeyError):
                pass
            if hour is not None and (hour < 5 or hour >= 23) and event == "successful_login":
                alerts.append({
                    "severity": "LOW",
                    "source_ip": ip,
                    "reason": f"Successful login at unusual sample hour ({hour:02d}:00)",
                    "recommendation": "Check whether this login time is expected; time alone does not prove an attack."
                })
    return alerts

def main():
    print("=" * 58)
    print(" AI-POWERED CYBER DEFENSE — EDUCATIONAL DEMO")
    print(" Synthetic data only | Rule-based demonstration")
    print("=" * 58)
    rows = load_logs()
    alerts = analyze_logs(rows)
    print(f"Sample events analyzed: {len(rows)}")
    print(f"Alerts generated: {len(alerts)}\n")
    if not alerts:
        print("No alerts generated from these sample rules.")
    for i, alert in enumerate(alerts, 1):
        print(f"{i}. [{alert['severity']}] Source: {alert['source_ip']}")
        print(f"   Reason: {alert['reason']}")
        print(f"   Suggested next step: {alert['recommendation']}\n")
    print("Limitations: this demo uses simple rules and synthetic logs.")
    print("It can produce false positives and does not replace professional security tools.")
    print("AI extension: paste the anonymized alert summary into Gemini/Copilot")
    print("to request a plain-language explanation; do not submit personal or sensitive data.")

if __name__ == "__main__":
    main()
