#!/usr/bin/env python3
"""
attack_tcp_client.py - Anomalous/Attack TCP Traffic Generator
"""

import argparse
import socket
import sys
import threading
import time

total_attempts = 0
total_success = 0
total_dropped = 0
running = True

def worker(host, port, timeout):
    global total_attempts, total_success, total_dropped
    while running:
        total_attempts += 1
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            s.sendall(b"GET /attack HTTP/1.1\r\n\r\n")
            total_success += 1
        except Exception:
            total_dropped += 1
        finally:
            try:
                s.close()
            except Exception:
                pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", default="10.0.0.1")
    parser.add_argument("-p", "--port", type=int, default=8080)
    parser.add_argument("--threads", type=int, default=5)
    args = parser.parse_args()

    for _ in range(args.threads):
        threading.Thread(target=worker, args=(args.target, args.port, 1.0), daemon=True).start()

    print(f"[ATTACKER] Flooding {args.target}:{args.port} with {args.threads} threads")
    try:
        while True:
            time.sleep(1.0)
            print(f"Attempts: {total_attempts} | Passed: {total_success} | Dropped: {total_dropped}")
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
