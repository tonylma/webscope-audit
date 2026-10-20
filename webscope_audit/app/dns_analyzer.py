import socket
from urllib.parse import urlsplit

import dns.exception
import dns.resolver


def dns_hostname(hostname: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(hostname, "A")
        return [str(item) for item in answers]
    except dns.exception.DNSException:
        return []


def validate_dns_target(hostname: str) -> tuple[bool, str | None]:
    try:
        socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        return False, str(exc)
    return True, None


def gather_dns_errors(hostname: str) -> list[str]:
    errors: list[str] = []
    for record_type in ("A", "AAAA", "CNAME", "MX", "NS", "TXT"):
        try:
            dns.resolver.resolve(hostname, record_type)
        except dns.exception.DNSException as exc:
            errors.append(f"{record_type}: {exc}")
    return errors


def safe_dns_target(hostname: str) -> bool:
    parts = hostname.split(".")
    if len(parts) < 2:
        return False
    return not hostname.startswith(".")
