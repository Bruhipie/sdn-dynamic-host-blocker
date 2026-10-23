#!/usr/bin/env python3
"""
controller.py - SDN Dynamic Host Blocker Controller
"""

import argparse
import re
import subprocess
import time

WHITELIST = {"10.0.0.1", "127.0.0.1"}

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

def run_controller(switch="s1", threshold=25.0, interval=1.0):
    print(f"Monitoring switch {switch} (Threshold: {threshold} pkts/s)...")
    prev_stats = {}
    prev_time = time.time()

    while True:
        time.sleep(interval)
        now = time.time()
        dt = max(now - prev_time, 0.001)
        stats = get_flow_stats(switch)
        for host, pkts in stats.items():
            prev = prev_stats.get(host, pkts)
            rate = (pkts - prev) / dt
            print(f"[Traffic Monitor] Host {host} -> {rate:.1f} pkts/s")
        prev_stats = stats
        prev_time = now

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--threshold", type=float, default=25.0)
    args = parser.parse_args()
    try:
        run_controller(threshold=args.threshold)
    except KeyboardInterrupt:
        pass
