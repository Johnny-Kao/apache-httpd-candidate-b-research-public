#!/usr/bin/env python3
"""Synchronized localhost backend for Candidate B."""

from __future__ import annotations

import socket
import time
from pathlib import Path


class Backend:
    def __init__(self, log_path: Path, test_case: str):
        self.log_path = log_path
        self.test_case = test_case
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.port = self.listener.getsockname()[1]
        self.connections = []

    def log(self, event: str, **fields: object) -> None:
        row = {"t": time.monotonic(), "event": event, **fields}
        with self.log_path.open("a", encoding="utf-8") as out:
            out.write(" ".join(f"{k}={v!r}" for k, v in row.items()) + "\n")

    def recv_request(self, conn: socket.socket, connection_id: str, request_no: int) -> bytes:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                raise RuntimeError("backend connection closed while reading request")
            data += chunk
            self.log("recv", connection=connection_id, request=request_no,
                     size=len(chunk), total=len(data))
        return data

    def send(self, conn: socket.socket, connection_id: str, data: bytes, phase: str) -> None:
        conn.sendall(data)
        self.log("send", connection=connection_id, phase=phase, size=len(data),
                 data=data.hex())

    def run(self) -> None:
        conn, address = self.listener.accept()
        connection_id = f"{address[0]}:{address[1]}"
        self.connections.append(connection_id)
        self.log("accept", connection=connection_id)
        try:
            self.recv_request(conn, connection_id, 1)
            a_headers = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
            if self.test_case == "close":
                a_headers += b"Connection: close\r\n"
            self.send(conn, connection_id, a_headers + b"\r\nOK", "A-final")
            if self.test_case in {"close", "nokeepalive"}:
                conn.close()
                conn, address = self.listener.accept()
                connection_id = f"{address[0]}:{address[1]}"
                self.connections.append(connection_id)
                self.log("accept", connection=connection_id)
            self.recv_request(conn, connection_id, 2)
            self.log("phase", name="B-request-observed", connection=connection_id)
            if self.test_case == "positive":
                self.send(conn, connection_id, b"HTTP/1.1 200 OK\r\nX-Poison: from-A\r\nContent-Length: 6\r\n\r\nPOISON", "A-delayed-remainder")
            self.send(conn, connection_id, b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nREALB", "B-legitimate")
        finally:
            self.log("close", connection=connection_id)
            conn.close()
            self.listener.close()
