import socket
from typing import Sequence


def scan_ports(hostname: str, ports: Sequence[int], timeout: float = 2.0) -> dict[str, list[int] | list[str]]:
    checked: list[int] = []
    open_ports: list[int] = []

    for port in ports:
        checked.append(port)
        try:
            with socket.create_connection((hostname, port), timeout=timeout):
                open_ports.append(port)
        except OSError:
            pass

    return {"checked": checked, "open": open_ports}
