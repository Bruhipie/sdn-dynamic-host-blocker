#!/usr/bin/env python3
"""
tcp_server.py - Multi-threaded TCP Target Server
"""

import socket
import sys
import threading
import time
from collections import defaultdict

stats_lock = threading.Lock()
total_connections = 0
connections_in_window = 0
client_counts = defaultdict(int)
running = True

def handle_client(sock, addr):
    global total_connections, connections_in_window
    with stats_lock:
        total_connections += 1
        connections_in_window += 1
        client_counts[addr[0]] += 1
    try:
        sock.settimeout(2.0)
        _ = sock.recv(1024)
        sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
    except Exception:
        pass
    finally:
        sock.close()

def stats_logger():
    global connections_in_window
    last = time.time()
    while running:
        time.sleep(2.0)
        now = time.time()
        with stats_lock:
            rate = connections_in_window / (now - last)
            connections_in_window = 0
        print(f"Throughput: {rate:.1f} conn/s | Total: {total_connections}")
        last = now

def run_server(host="10.0.0.1", port=8080):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(128)
    threading.Thread(target=stats_logger, daemon=True).start()
    print(f"TCP server ready on {host}:{port}")
    try:
        while running:
            client, addr = server.accept()
            threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()
    except KeyboardInterrupt:
        server.close()

if __name__ == "__main__":
    run_server()
