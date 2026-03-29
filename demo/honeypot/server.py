from __future__ import annotations

import socket
import threading


def handle_client(conn: socket.socket, address: tuple[str, int]) -> None:
    try:
        banner = f"SSH-2.0-VESTA-Honeypot from {address[0]}\r\n".encode("utf-8")
        conn.sendall(banner)
        conn.sendall(b"login: ")
        conn.recv(512)
        conn.sendall(b"password: ")
        conn.recv(512)
        conn.sendall(b"Access denied\r\n")
    except Exception:
        pass
    finally:
        conn.close()


def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 2222))
    sock.listen(25)
    while True:
        conn, address = sock.accept()
        thread = threading.Thread(target=handle_client, args=(conn, address), daemon=True)
        thread.start()


if __name__ == "__main__":
    main()

