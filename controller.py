#!/usr/bin/env python3
"""
controller.py - SDN Dynamic Host Blocker Controller

SDN Security Controller using Open vSwitch (ovs-ofctl):
  - Initializes baseline forwarding and per-host flow counters on switch s1.
  - Periodically queries switch flow statistics and calculates per-host packet rate.
  - Detects traffic rate anomalies (>= threshold), installs high-priority OpenFlow
    DROP flow rules at the switch, and records security audit logs.
  - Automatically unblocks hosts after a period of inactivity (Dynamic Recovery).
"""

import argparse
import json
import re
import subprocess
import time
from datetime import datetime, timezone

# Protected hosts that should never be blocked (e.g., target server)
WHITELIST = {"10.0.0.1", "127.0.0.1"}

# Known client hosts to monitor
MONITORED_HOSTS = ["10.0.0.2", "10.0.0.3", "10.0.0.4"]


def init_switch(switch="s1"):
    """Installs baseline forwarding and per-host monitoring flows on switch s1."""
    try:
        # Base forwarding rule
        subprocess.run(["ovs-ofctl", "add-flow", switch, "priority=1,actions=normal"],
                       stderr=subprocess.DEVNULL, check=False)
        # Per-host IP rules to track individual packet counters
        for ip in MONITORED_HOSTS:
            subprocess.run(
                ["ovs-ofctl", "add-flow", switch, f"priority=10,ip,nw_src={ip},actions=normal"],
                stderr=subprocess.DEVNULL, check=False
            )
    except Exception:
        pass


def get_flow_stats(switch="s1"):
    """Queries switch s1 using ovs-ofctl and returns total packets per source IP."""
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
            packets = int(pkt_match.group(1))
            src_ip = ip_match.group(1)
            if src_ip not in WHITELIST:
                stats[src_ip] = stats.get(src_ip, 0) + packets

    return stats


def install_drop_rule(offender_ip, switch="s1", priority=50000, idle_timeout=15):
    """Pushes a high-priority OpenFlow DROP rule with idle_timeout to switch s1."""
    rule = f"priority={priority},idle_timeout={int(idle_timeout)},tcp,nw_src={offender_ip},actions=drop"
    subprocess.run(["ovs-ofctl", "add-flow", switch, rule], check=True)


def remove_drop_rule(offender_ip, switch="s1"):
    """Removes the OpenFlow DROP rule for a recovered host."""
    try:
        subprocess.run(["ovs-ofctl", "del-flows", switch, f"tcp,nw_src={offender_ip}"],
                       stderr=subprocess.DEVNULL, check=False)
    except Exception:
        pass


def log_audit_event(offender_ip, rate_pps, threshold_pps, priority=50000, idle_timeout=15):
    """Records security incident into audit_log.json and prints alert."""
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "TCP_ANOMALY_FLOOD_DETECTED",
        "offender_ip": offender_ip,
        "rate_pps": round(rate_pps, 1),
        "threshold_pps": threshold_pps,
        "action": "INSTALL_OPENFLOW_DROP_RULE",
        "openflow_priority": priority,
        "idle_timeout_sec": idle_timeout,
        "flow_rule": f"priority={priority},idle_timeout={idle_timeout},tcp,nw_src={offender_ip},actions=drop",
        "status": "BLOCKED_AT_SWITCH",
    }

    banner = (
        "\n" + "=" * 70 + "\n"
        "[SECURITY ALERT] ABNORMAL TCP FLOOD DETECTED\n"
        + "-" * 70 + "\n"
        f"Offending Host: \033[1;31m{offender_ip}\033[0m\n"
        f"Observed Rate:  \033[1;33m{rate_pps:.1f} pkts/s\033[0m (Threshold: {threshold_pps} pkts/s)\n"
        f"Mitigation:     Installed OpenFlow DROP rule on switch s1 (Priority: {priority})\n"
        f"Auto-Recovery:  Rule will expire after {idle_timeout}s of inactivity\n"
        f"Rule Injected:  priority={priority},idle_timeout={idle_timeout},tcp,nw_src={offender_ip},actions=drop\n"
        f"Audit Log:      Saved to audit_log.json\n"
        + "=" * 70 + "\n"
    )
    print(banner, flush=True)

    with open("audit_log.json", "a") as f:
        f.write(json.dumps(record) + "\n")


def log_recovery_event(recovered_ip, idle_timeout):
    """Records automatic recovery/unblock event after period of inactivity."""
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "HOST_RECOVERY_UNBLOCKED",
        "recovered_ip": recovered_ip,
        "inactivity_period_sec": idle_timeout,
        "action": "REMOVE_OPENFLOW_DROP_RULE",
        "status": "RECOVERED_ACTIVE",
    }

    banner = (
        "\n" + "-" * 70 + "\n"
        "[SECURITY NOTICE] DYNAMIC HOST RECOVERY\n"
        f"Host {recovered_ip} unblocked after {idle_timeout}s of inactivity.\n"
        "Normal communication restored at switch s1.\n"
        + "-" * 70 + "\n"
    )
    print(banner, flush=True)

    with open("audit_log.json", "a") as f:
        f.write(json.dumps(record) + "\n")


def run_controller(switch="s1", threshold=25.0, interval=1.0, timeout=15.0):
    print("=" * 70)
    print(f"SDN Security Controller Active on Switch '{switch}'")
    print(f"Stats Polling Interval: {interval}s")
    print(f"Drop Rate Threshold:    >= {threshold} pkts/s")
    print(f"Inactivity Auto-Unblock: {timeout}s")
    print("=" * 70)

    # Initialize switch flow tables
    init_switch(switch)

    prev_stats = {}
    prev_time = time.time()
    # Track blocked hosts: {ip: last_active_timestamp}
    blocked_hosts = {}

    try:
        while True:
            time.sleep(interval)
            now = time.time()
            dt = max(now - prev_time, 0.001)

            curr_stats = get_flow_stats(switch)
            if not curr_stats:
                init_switch(switch)
                print("[Traffic Monitor] Waiting for traffic on switch s1...")
                prev_time = now
                continue

            for host_ip in MONITORED_HOSTS:
                total_pkts = curr_stats.get(host_ip, 0)
                prev_pkts = prev_stats.get(host_ip, total_pkts)
                rate_pps = max(total_pkts - prev_pkts, 0) / dt

                is_blocked = host_ip in blocked_hosts

                # Check for auto-recovery: If blocked host was inactive for timeout seconds
                if is_blocked:
                    if rate_pps == 0:
                        last_active = blocked_hosts[host_ip]
                        if now - last_active >= timeout:
                            remove_drop_rule(host_ip, switch=switch)
                            log_recovery_event(host_ip, timeout)
                            del blocked_hosts[host_ip]
                            is_blocked = False
                    else:
                        # Reset inactivity timer if host still sends packets
                        blocked_hosts[host_ip] = now

                # Display active rates
                status = "BLOCKED" if is_blocked else "ACTIVE"
                print(f"[Traffic Monitor] Host {host_ip:<12} -> {rate_pps:>6.1f} pkts/s [{status}] (Total: {total_pkts})")

                # Detect threshold breach and block
                if rate_pps >= threshold and not is_blocked:
                    blocked_hosts[host_ip] = now
                    install_drop_rule(host_ip, switch=switch, idle_timeout=timeout)
                    log_audit_event(host_ip, rate_pps, threshold, idle_timeout=timeout)

            prev_stats = curr_stats
            prev_time = now

    except KeyboardInterrupt:
        print("\nController shutting down...")
        if blocked_hosts:
            blocked_list = ", ".join(sorted(blocked_hosts.keys()))
            print(f"Active blocked host(s): {blocked_list}")
            try:
                choice = input("Clear active DROP rules from switch s1? (y/n) [default: y]: ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                choice = "y"

            if choice in ("", "y", "yes"):
                for ip in list(blocked_hosts.keys()):
                    remove_drop_rule(ip, switch=switch)
                print("Active DROP flow rules cleared from switch.")
            else:
                print("Active DROP flow rules preserved on switch.")
        print("Controller stopped.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SDN Dynamic Host Blocker Controller")
    parser.add_argument("--switch", type=str, default="s1", help="Switch name (default: s1)")
    parser.add_argument("--threshold", type=float, default=25.0, help="Rate threshold in pkts/s (default: 25.0)")
    parser.add_argument("--interval", type=float, default=1.0, help="Stats polling interval in seconds (default: 1.0)")
    parser.add_argument("--timeout", type=float, default=15.0, help="Inactivity auto-unblock period in seconds (default: 15.0)")
    args = parser.parse_args()

    run_controller(switch=args.switch, threshold=args.threshold, interval=args.interval, timeout=args.timeout)
