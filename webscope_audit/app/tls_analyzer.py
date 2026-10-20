from __future__ import annotations

import socket
import ssl
from datetime import datetime
from typing import Any


def analyze_tls(hostname: str, port: int = 443, timeout: float = 10.0) -> dict[str, Any]:
    certificate = {
        "issuer": None,
        "subject": None,
        "dns_names": [],
        "not_before": None,
        "not_after": None,
        "valid": False,
        "validation_status": "unknown",
    }
    errors: list[str] = []

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                if cert:
                    certificate["issuer"] = cert.get("issuer")
                    certificate["subject"] = cert.get("subject")
                    certificate["dns_names"] = [name for key, name in cert.get("subjectAltName", []) if key == "DNS"]
                    certificate["not_before"] = cert.get("notBefore")
                    certificate["not_after"] = cert.get("notAfter")
                    certificate["valid"] = True
                    certificate["validation_status"] = "valid"
                else:
                    certificate["validation_status"] = "no_certificate"
    except Exception as exc:  # pragma: no cover - environment-dependent
        errors.append(str(exc))
        certificate["validation_status"] = "error"

    return {
        "hostname": hostname,
        "port": port,
        "certificate": certificate,
        "errors": errors,
        "collected_at": datetime.utcnow().isoformat() + "Z",
    }
