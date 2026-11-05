"""
Generates synthetic security event logs for the SOC metrics dashboard.
Run once before launching the dashboard: python generate_logs.py
"""

import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

ATTACK_PROFILES = {
    "brute_force":        {"weight": 25, "severities": {"high": 0.60, "medium": 0.30, "critical": 0.10}},
    "port_scan":          {"weight": 20, "severities": {"low":  0.40, "medium": 0.50, "high":    0.10}},
    "phishing_attempt":   {"weight": 18, "severities": {"medium": 0.50, "high": 0.35, "critical": 0.15}},
    "malware_detected":   {"weight": 12, "severities": {"high": 0.40, "critical": 0.50, "medium": 0.10}},
    "unauthorized_access":{"weight": 10, "severities": {"high": 0.55, "critical": 0.30, "medium": 0.15}},
    "privilege_escalation":{"weight": 8, "severities": {"critical": 0.70, "high": 0.30}},
    "suspicious_outbound":{"weight":  7, "severities": {"medium": 0.60, "high": 0.30, "low": 0.10}},
}

STATUS_DIST = {
    "blocked":      0.40,
    "detected":     0.35,
    "escalated":    0.12,
    "investigating":0.08,
    "resolved":     0.05,
}

HOSTS = (
    [f"WIN-SRV-{i:03d}" for i in range(1, 16)]
    + [f"LNX-WEB-{i:02d}" for i in range(1, 9)]
    + [f"DB-NODE-{i:02d}" for i in range(1, 5)]
)


def _pick(dist: dict) -> str:
    keys, weights = zip(*dist.items())
    return random.choices(keys, weights=weights, k=1)[0]


def _ip(internal: bool = False) -> str:
    if internal:
        return f"10.{random.randint(0,5)}.{random.randint(0,255)}.{random.randint(1,254)}"
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _event(ts: datetime, event_type: str | None = None) -> dict:
    if event_type is None:
        event_type = _pick({k: v["weight"] for k, v in ATTACK_PROFILES.items()})
    return {
        "timestamp":      ts.strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip":      _ip(internal=random.random() < 0.12),
        "destination_ip": _ip(internal=True),
        "event_type":     event_type,
        "severity":       _pick(ATTACK_PROFILES[event_type]["severities"]),
        "host":           random.choice(HOSTS),
        "status":         _pick(STATUS_DIST),
    }


def generate(n: int = 12000, days: int = 30, seed: int = 42) -> list[dict]:
    random.seed(seed)
    end   = datetime.now().replace(microsecond=0)
    start = end - timedelta(days=days)
    span  = int((end - start).total_seconds())

    events = []

    # Baseline events with business-hours weighting
    for _ in range(n):
        ts = start + timedelta(seconds=random.randint(0, span))
        # Weekday 08:00–18:00 gets ~45% of traffic redistributed inward
        if ts.weekday() < 5 and 8 <= ts.hour < 18 and random.random() < 0.45:
            ts = ts.replace(hour=random.randint(8, 17), minute=random.randint(0, 59))
        events.append(_event(ts))

    # Attack spikes — 5 concentrated bursts from a single IP, 2-hour windows
    # Creates visible anomalies in the daily volume and top-IPs charts
    spike_types = random.sample(list(ATTACK_PROFILES.keys()), 5)
    for attack_type in spike_types:
        spike_start  = start + timedelta(seconds=random.randint(0, span - 7200))
        attacker_ip  = _ip()
        spike_count  = random.randint(150, 280)
        for _ in range(spike_count):
            ts = spike_start + timedelta(seconds=random.randint(0, 7200))
            ev = _event(ts, event_type=attack_type)
            ev["source_ip"] = attacker_ip
            events.append(ev)

    events.sort(key=lambda e: e["timestamp"])
    return events


def main() -> None:
    Path("data").mkdir(exist_ok=True)
    events = generate()
    out = Path("data/security_events.csv")
    with out.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(events[0].keys()))
        writer.writeheader()
        writer.writerows(events)
    print(f"Generated {len(events):,} events -> {out}")


if __name__ == "__main__":
    main()
