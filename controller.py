#!/usr/bin/env python3
"""
controller.py - SDN Dynamic Host Blocker Controller
"""

import argparse
import json
import re
import subprocess
import time
from datetime import datetime, timezone

WHITELIST = {"10.0.0.1", "127.0.0.1"}
MONITORED_HOSTS = ["10.0.0.2", "10.0.0.3", "10.0.0.4"]

def init_switch(switch="s1"):
    try:
        subprocess.run(["ovs-ofctl", "add-flow", switch, "priority=1,actions=normal"], stderr=subprocess.DEVNULL)
        for ip in MONITORED_HOSTS:
            subprocess.run(["ovs-ofctl", "add-flow", switch, f"priority=10,ip,nw_src={ip},actions=normal"], stderr=subprocess.DEVNULL)
    except Exception:
        pass

def get_flow_stats(switch="s1"):
    cmd = ["ovs-ofctl", "dump-flows", switch]
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except Exception:
        return {}
    stats = {}
    for line in output.splitlines():
        pkt_match = re.search(r"n_packets=(\d+)", line)
        ip_match = re.search(r"(?:nw_src|ipv4_src)=([0-9.]+)", line)
        if pkt_match and ip_match:
            ip = ip_match.group(1)
            if ip not in WHITELIST:
                stats[ip] = stats.get(ip, 0) + int(pkt_match.group(1))
    return stats

def install_drop_rule(offender_ip, switch="s1", priority=50000):
    rule = f"priority={priority},tcp,nw_src={offender_ip},actions=drop"
    subprocess.run(["ovs-ofctl", "add-flow", switch, rule], check=True)

def log_audit_event(offender_ip, rate_pps, threshold_pps, priority=50000):
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "TCP_ANOMALY_FLOOD_DETECTED",
        "offender_ip": offender_ip,
        "rate_pps": round(rate_pps, 1),
        "threshold_pps": threshold_pps,
        "action": "INSTALL_OPENFLOW_DROP_RULE",
        "openflow_priority": priority,
        "flow_rule": f"priority={priority},tcp,nw_src={offender_ip},actions=drop",
        "status": "BLOCKED_AT_SWITCH",
    }
    banner = (
        "\n" + "=" * 70 + "\n"
        "[SECURITY ALERT] ABNORMAL TCP FLOOD DETECTED\n"
        + "-" * 70 + "\n"
        f"Offending Host: \033[1;31m{offender_ip}\033[0m\n"
        f"Observed Rate:  \033[1;33m{rate_pps:.1f} pkts/s\033[0m (Threshold: {threshold_pps} pkts/s)\n"
        f"Mitigation:     Installed OpenFlow DROP rule on switch s1 (Priority: {priority})\n"
        f"Rule Injected:  priority={priority},tcp,nw_src={offender_ip},actions=drop\n"
        f"Audit Log:      Saved to audit_log.json\n"
        + "=" * 70 + "\n"
    )
    print(banner, flush=True)
    with open("audit_log.json", "a") as f:
        f.write(json.dumps(record) + "\n")

def run_controller(switch="s1", threshold=25.0, interval=1.0):
    init_switch(switch)
    prev_stats = {}
    prev_time = time.time()
    blocklist = set()

    while True:
        time.sleep(interval)
        now = time.time()
        dt = max(now - prev_time, 0.001)
        curr_stats = get_flow_stats(switch)
        for host in MONITORED_HOSTS:
            pkts = curr_stats.get(host, 0)
            rate = max(pkts - prev_stats.get(host, pkts), 0) / dt
            status = "BLOCKED" if host in blocklist else "ACTIVE"
            print(f"[Traffic Monitor] Host {host:<12} -> {rate:>6.1f} pkts/s [{status}] (Total: {pkts})")
            if rate >= threshold and host not in blocklist:
                blocklist.add(host)
                install_drop_rule(host, switch=switch)
                log_audit_event(host, rate, threshold)
        prev_stats = curr_stats
        prev_time = now

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--threshold", type=float, default=25.0)
    args = parser.parse_args()
    try:
        run_controller(threshold=args.threshold)
    except KeyboardInterrupt:
        pass
