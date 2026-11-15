from __future__ import annotations

import os
import socket

def scan_with_clamav(content: bytes, timeout: int = 45) -> dict:
    """Stream bytes to clamd INSTREAM. No sample is written to disk or executed."""
    host = os.getenv("CLAMAV_HOST", "clamav")
    port = int(os.getenv("CLAMAV_PORT", "3310"))
    max_bytes = int(os.getenv("CLAMAV_MAX_BYTES", "25000000"))
    if len(content) > max_bytes:
        return {"status": "not_scanned", "reason": "file_too_large_for_antivirus", "engine": "ClamAV"}
    try:
        with socket.create_connection((host, port), timeout=timeout) as client:
            client.settimeout(timeout)
            client.sendall(b"zINSTREAM\0")
            view = memoryview(content)
            offset = 0
            while offset < len(content):
                chunk = view[offset:offset + 64 * 1024]
                client.sendall(len(chunk).to_bytes(4, "big"))
                client.sendall(chunk)
                offset += len(chunk)
            client.sendall((0).to_bytes(4, "big"))
            chunks = []
            while True:
                packet = client.recv(4096)
                if not packet:
                    break
                chunks.append(packet)
                if b"\0" in packet or len(chunks) > 16:
                    break
        response = b"".join(chunks).decode("utf-8", errors="replace").strip("\0\r\n ")
        if response.endswith("OK"):
            return {"status": "clean_by_signatures", "engine": "ClamAV", "signature_response": response}
        if " FOUND" in response:
            return {"status": "malware_detected", "engine": "ClamAV", "signature_response": response}
        return {"status": "scan_error", "engine": "ClamAV", "signature_response": response[:500]}
    except (OSError, TimeoutError) as exc:
        return {"status": "not_configured_or_unavailable", "engine": "ClamAV", "reason": type(exc).__name__}
