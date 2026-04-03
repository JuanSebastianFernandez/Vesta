from __future__ import annotations

import datetime
import socket
import threading


def _log(message: str) -> None:
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    print(f"[{timestamp}] {message}", flush=True)


def handle_client(conn: socket.socket, address: tuple[str, int]) -> None:
    try:
        _log(f"connection accepted from {address[0]}:{address[1]}")
        banner = f"SSH-2.0-VESTA-Honeypot from {address[0]}\r\n".encode("utf-8")
        conn.sendall(banner)
        conn.sendall(b"login: ")
        username = conn.recv(512).decode("utf-8", errors="ignore").strip()
        _log(f"username probe from {address[0]}:{address[1]} value='{username[:80]}'")
        conn.sendall(b"password: ")
        password = conn.recv(512).decode("utf-8", errors="ignore").strip()
        _log(f"password probe from {address[0]}:{address[1]} length={len(password)}")
        conn.sendall(b"Access denied\r\n")
    except Exception:
        _log(f"connection handling failed for {address[0]}:{address[1]}")
    finally:
        conn.close()
        _log(f"connection closed for {address[0]}:{address[1]}")


def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 2222))
    sock.listen(25)
    _log("honeypot listening on 0.0.0.0:2222")
    while True:
        conn, address = sock.accept()
        thread = threading.Thread(target=handle_client, args=(conn, address), daemon=True)
        thread.start()


if __name__ == "__main__":
    main()
