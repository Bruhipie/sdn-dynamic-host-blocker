#!/usr/bin/env python3
"""
tcp_server.py - Basic TCP Target Server
"""

import socket
import sys

def main():
    host = "10.0.0.1"
    port = 8080
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, port))
    sock.listen(5)
    print(f"Server listening on {host}:{port}")

    while True:
        conn, addr = sock.accept()
        data = conn.recv(1024)
        if data:
            conn.sendall(b"OK")
        conn.close()

if __name__ == "__main__":
    main()
