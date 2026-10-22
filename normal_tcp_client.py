#!/usr/bin/env python3
"""
normal_tcp_client.py - Legitimate Client for SDN Dynamic Host Blocker Project

Runs on legitimate client hosts (h2: 10.0.0.2, h3: 10.0.0.3).
Sends polite, periodic TCP connection requests to the server (default: 10.0.0.1:8080)
at regular intervals (e.g. 1-2 seconds) to simulate continuous baseline traffic.
Reports RTT latency and connection status.
"""

import argparse
import socket
import sys
import time

running = True


def run_client(
    target_host: str,
    target_port: int,
    interval: float = 1.0,
    count: int = 0,
    timeout: float = 2.0,
    client_name: str = "Client",
):
    global running

    print("============================================================")
    print(f" [{client_name}] Starting Normal TCP Traffic")
    print(f" Target: {target_host}:{target_port}")
    print(f" Interval: {interval}s | Timeout: {timeout}s | Max Count: {'Infinite' if count <= 0 else count}")
    print(" Press Ctrl+C to terminate cleanly")
    print("============================================================")
    sys.stdout.flush()

    attempts = 0
    successful = 0
    failed = 0
    total_rtt = 0.0

    request_payload = b"GET / HTTP/1.1\r\nHost: sdn-target\r\nConnection: close\r\n\r\n"

    try:
        while running:
            attempts += 1
            start_time = time.time()
            status = "UNKNOWN"
            rtt_ms = 0.0

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            try:
                sock.connect((target_host, target_port))
                sock.sendall(request_payload)
                _ = sock.recv(1024)
                rtt_ms = (time.time() - start_time) * 1000.0
                status = "SUCCESS"
                successful += 1
                total_rtt += rtt_ms
            except socket.timeout:
                status = "TIMEOUT (Dropped / Unreachable)"
                failed += 1
            except ConnectionRefusedError:
                status = "CONNECTION REFUSED"
                failed += 1
            except OSError as e:
                status = f"ERROR: {e}"
                failed += 1
            finally:
                try:
                    sock.close()
                except Exception:
                    pass

            timestamp = time.strftime("%H:%M:%S")
            if status == "SUCCESS":
                print(f"[{timestamp}] Seq #{attempts:4d} | Status: {status:7s} | RTT: {rtt_ms:6.2f} ms")
            else:
                print(f"[{timestamp}] Seq #{attempts:4d} | Status: {status}")
            sys.stdout.flush()

            if count > 0 and attempts >= count:
                break

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n[INFO] Stopped by user.")
    finally:
        avg_rtt = (total_rtt / successful) if successful > 0 else 0.0
        success_rate = (successful / attempts * 100.0) if attempts > 0 else 0.0

        print("\n============================================================")
        print(f" [{client_name}] Session Summary:")
        print(f" Total Attempts:      {attempts}")
        print(f" Successful:          {successful}")
        print(f" Failed / Dropped:    {failed}")
        print(f" Success Rate:        {success_rate:.1f}%")
        print(f" Average Latency:     {avg_rtt:.2f} ms")
        print("============================================================")


def main():
    parser = argparse.ArgumentParser(description="Normal TCP Client (h2, h3)")
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
        "-i",
        "--interval",
        type=float,
        default=1.0,
        help="Interval between requests in seconds (default: 1.0)",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Number of requests to send (default: 0 for infinite)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Socket timeout in seconds (default: 2.0)",
    )
    parser.add_argument(
        "--name",
        type=str,
        default="NormalClient",
        help="Identifier name for output logging",
    )

    args = parser.parse_args()
    run_client(
        target_host=args.target,
        target_port=args.port,
        interval=args.interval,
        count=args.count,
        timeout=args.timeout,
        client_name=args.name,
    )


if __name__ == "__main__":
    main()
