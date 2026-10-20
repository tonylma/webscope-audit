import ssl
from typing import Any, Dict


def inspect_tls(hostname: str, port: int = 443) -> Dict[str, Any]:
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(ssl.socket.create_connection((hostname, port), timeout=5), server_hostname=hostname) as sock:
            cert = sock.getpeercert()
            return {
                'host': hostname,
                'port': port,
                'issuer': cert.get('issuer', {}),
                'subject': cert.get('subject', {}),
                'version': sock.version(),
                'cipher': sock.cipher(),
            }
    except Exception as exc:
        return {'host': hostname, 'port': port, 'error': str(exc)}
