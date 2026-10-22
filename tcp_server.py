#!/usr/bin/env python3
"""
tcp_server.py - TCP Server for SDN Dynamic Host Blocker Project

Runs on the target server host (h1, 10.0.0.1).
Accepts incoming TCP connections, logs client details, responds with a lightweight ACK,
and tracks real-time traffic statistics (total connections, rate per second, and per-client breakdown).
"""

import argparse
import socket
import sys
import threading
import time
from collections import defaultdict

# Global connection statistics
stats_lock = threading.Lock()
total_connections = 0
connections_in_window = 0
client_connection_counts = defaultdict(int)
running = True


def connection_handler(client_sock: socket.socket, client_addr: tuple, response_payload: bytes):
    """Handles an individual client TCP connection cleanly."""
    global total_connections, connections_in_window
    client_ip, client_port = client_addr

    with stats_lock:
        total_connections += 1
        connections_in_window += 1
        client_connection_counts[client_ip] += 1

    try:
        client_sock.settimeout(2.0)
        # Optional: read up to 1024 bytes if client sent data
        try:
            _ = client_sock.recv(1024)
        except (socket.timeout, ConnectionResetError):
            pass

        # Send response and close connection cleanly
        if response_payload:
            client_sock.sendall(response_payload)
    except Exception:
        # Ignore write failures if client abruptly closed
        pass
    finally:
        try:
            client_sock.close()
        except Exception:
            pass


def stats_reporter(interval_seconds: float = 2.0):
    """Background thread printing live server throughput & per-client stats."""
    global connections_in_window
    last_time = time.time()

    while running:
        time.sleep(interval_seconds)
        now = time.time()
        elapsed = now - last_time

        with stats_lock:
            rate = connections_in_window / elapsed if elapsed > 0 else 0
            current_total = total_connections
            client_snapshot = dict(client_connection_counts)
            connections_in_window = 0

        last_time = now

        client_breakdown = ", ".join(f"{ip}: {cnt}" for ip, cnt in sorted(client_snapshot.items()))
        if not client_breakdown:
            client_breakdown = "None"

        print(
            f"[{time.strftime('%H:%M:%S')}] "
            f"Rate: {rate:6.1f} conn/s | "
            f"Total: {current_total:7d} | "
            f"Per-Host: {client_breakdown}"
        )
        sys.stdout.flush()


def run_server(host: str, port: int, backlog: int = 1024, stats_interval: float = 2.0):
    """Main TCP listening server loop."""
    global running

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_sock.bind((host, port))
        server_sock.listen(backlog)
    except Exception as e:
        print(f"[ERROR] Failed to bind/listen on {host}:{port} - {e}", file=sys.stderr)
        sys.exit(1)

    print(f"============================================================")
    print(f" TCP Server Started on {host}:{port}")
    print(f" Backlog: {backlog} | Stats Interval: {stats_interval}s")
    print(f" Press Ctrl+C to terminate cleanly")
    print(f"============================================================")
    sys.stdout.flush()

    # Minimal payload: standard HTTP 200 / simple ACK
    response_payload = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"

    # Start stats reporter thread
    stats_thread = threading.Thread(target=stats_reporter, args=(stats_interval,), daemon=True)
    stats_thread.start()

    try:
        while running:
            try:
                client_sock, client_addr = server_sock.accept()
                t = threading.Thread(
                    target=connection_handler,
                    args=(client_sock, client_addr, response_payload),
                    daemon=True,
                )
                t.start()
            except socket.error as e:
                if running:
                    print(f"[WARN] Socket accept error: {e}")
    except KeyboardInterrupt:
        print("\n[INFO] Termination requested. Shutting down server...")
    finally:
        running = False
        try:
            server_sock.close()
        except Exception:
            pass

        print(f"============================================================")
        print(f" Server Stopped. Final Summary:")
        print(f" Total Connections Received: {total_connections}")
        for ip, cnt in sorted(client_connection_counts.items()):
            print(f"   - {ip}: {cnt} connections")
        print(f"============================================================")


def main():
    parser = argparse.ArgumentParser(description="SDN Project TCP Server (h1)")
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="IP address to bind server (default: 0.0.0.0)",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=8080,
        help="TCP port to listen on (default: 8080)",
    )
    parser.add_argument(
        "--backlog",
        type=int,
        default=1024,
        help="Socket listen backlog queue size (default: 1024)",
    )
    parser.add_argument(
        "--stats-interval",
        type=float,
        default=2.0,
        help="Seconds between throughput log prints (default: 2.0)",
    )

    args = parser.parse_args()
    run_server(
        host=args.host,
        port=args.port,
        backlog=args.backlog,
        stats_interval=args.stats_interval,
    )


if __name__ == "__main__":
    main()
