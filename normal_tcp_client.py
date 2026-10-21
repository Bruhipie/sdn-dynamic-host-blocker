#!/usr/bin/env python3
"""
normal_tcp_client.py - Legitimate Client for SDN Dynamic Host Blocker Project
"""

import argparse
import socket
import time

def run_client(target_host="10.0.0.1", target_port=8080, interval=1.0, client_name="Client"):
    print(f"[{client_name}] Starting periodic requests to {target_host}:{target_port} every {interval}s")
    while True:
        t0 = time.time()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((target_host, target_port))
            s.sendall(b"GET / HTTP/1.1\r\n\r\n")
            _ = s.recv(1024)
            s.close()
            rtt = (time.time() - t0) * 1000
            print(f"[{client_name}] Connection successful (RTT: {rtt:.2f}ms)")
        except Exception as e:
            print(f"[{client_name}] Connection failed: {e}")
        time.sleep(interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", default="10.0.0.1")
    parser.add_argument("-p", "--port", type=int, default=8080)
    parser.add_argument("-i", "--interval", type=float, default=1.0)
    parser.add_argument("--name", default="Client")
    args = parser.parse_args()
    run_client(args.target, args.port, args.interval, args.name)
