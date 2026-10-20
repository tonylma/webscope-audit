from __future__ import annotations

import socket
import ssl
from datetime import datetime
from typing import Any


def analyze_tls(hostname: str, port: int = 443, timeout: float = 10.0) -> dict[str, Any]:
    errors: list[str] = []
    certificate: dict[str, Any] = {
        "issuer": None,
        "subject": None,
        "dns_names": [],
        "not_before": None,
        "not_after": None,
        "valid": False,
        "validation_status": "unknown",
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                peer_cert = ssock.getpeercert()
                if peer_cert:
                    certificate["issuer"] = peer_cert.get("issuer")
                    certificate["subject"] = peer_cert.get("subject")
                    certificate["dns_names"] = peer_cert.get("subjectAltName", [])
                    certificate["dns_names"] = [item[1] for item in certificate["dns_names"] if item[0] == "DNS"]
                    certificate["not_before"] = peer_cert.get("notBefore")
                    certificate["not_after"] = peer_cert.get("notAfter")
                    if certificate["not_before"] and certificate["not_after"]:
                        certificate["valid"] = True
                        certificate["validation_status"] = "valid"
                else:
                    certificate["validation_status"] = "no_certificate"
    except Exception as exc:  # pragma: no cover - depends on runtime TLS environment
        errors.append(str(exc))
        certificate["validation_status"] = "error"

    return {
        "hostname": hostname,
        "port": port,
        "certificate": certificate,
        "errors": errors,
        "collected_at": datetime.utcnow().isoformat() + "Z",
    }
