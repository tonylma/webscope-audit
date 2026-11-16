from __future__ import annotations

import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone
from http.client import HTTPResponse
from typing import Any
from urllib.parse import quote, urljoin, urlsplit

import dns.resolver
from bs4 import BeautifulSoup

from app.services.defense_engine import analyze_url
from app.core.config import get_settings

MAX_RESPONSE_BYTES = 64 * 1024
MAX_PATH_PROBES = min(14, get_settings().max_urls_per_scan)
MAX_URLS_TO_RETURN = get_settings().max_urls_per_scan
REQUEST_TIMEOUT = float(get_settings().timeout_seconds)
MAX_SUBDOMAINS = 12

COMMON_SUBDOMAINS = (
    "www", "api", "app", "m", "mobile", "portal", "cdn", "static", "assets",
    "mail", "support", "status", "blog", "shop", "staging", "dev",
)
COMMON_PATHS = (
    "/.env", "/.git/HEAD", "/backup.zip", "/backup.tar.gz", "/config",
    "/debug", "/admin", "/admin-console", "/swagger", "/openapi.json",
    "/server-status", "/actuator/health", "/robots.txt", "/sitemap.xml",
)
SENSITIVE_PATHS = {
    "/.env", "/.git/HEAD", "/backup.zip", "/backup.tar.gz", "/config", "/debug",
    "/server-status", "/actuator/health",
}

def _validate_target(raw_url: str) -> tuple[str, str, int, str]:
    if not raw_url or len(raw_url) > 2048:
        raise ValueError("URL absente ou trop longue (2048 caractères maximum).")
    if any(ord(char) < 32 or ord(char) == 127 for char in raw_url) or "\\" in raw_url:
        raise ValueError("URL contenant des caractères de contrôle.")
    try:
        parsed = urlsplit(raw_url.strip())
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL mal formée.") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Une URL HTTP(S) publique complète est obligatoire.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Les URL contenant des identifiants intégrés sont interdites.")
    hostname = parsed.hostname.rstrip(".")
    if not hostname or hostname.lower() in {"localhost", "localhost.localdomain"}:
        raise ValueError("Les hôtes locaux ne sont pas des cibles autorisées.")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("Les adresses IP littérales ne sont pas acceptées ; utilisez un nom DNS public.")
    try:
        hostname = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Nom DNS internationalisé invalide.") from exc
    if "." not in hostname or hostname.endswith((".local", ".internal", ".localhost", ".test", ".invalid")):
        raise ValueError("Un nom DNS public pleinement qualifié est obligatoire.")
    expected_port = 443 if scheme == "https" else 80
    if port not in (None, expected_port):
        raise ValueError("Seuls les ports standards 80/443 sont autorisés.")
    parsed_path = parsed.path or "/"
    if any(ord(char) < 32 or ord(char) == 127 for char in parsed_path + parsed.query):
        raise ValueError("Chemin ou paramètres d'URL invalides.")
    return scheme, hostname, expected_port, raw_url.strip()

def _resolve_public_addresses(hostname: str) -> list[str]:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 1.0
    resolver.lifetime = 2.0
    addresses: set[str] = set()
    for record_type in ("A", "AAAA"):
        try:
            answers = resolver.resolve(hostname, record_type, lifetime=2.0)
            addresses.update(str(answer) for answer in answers)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
    if not addresses:
        raise ValueError("Le domaine ne possède aucune adresse A/AAAA résoluble.")
    for value in addresses:
        address = ipaddress.ip_address(value)
        if not address.is_global:
            raise ValueError(f"Résolution DNS refusée : {hostname} renvoie une adresse non publique.")
    return sorted(addresses)

def _connection_for_address(ip: str, port: int, hostname: str, scheme: str, timeout: float):
    address = ipaddress.ip_address(ip)
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    raw = socket.socket(family, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    target = (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port)
    try:
        raw.connect(target)
        if scheme == "https":
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            wrapped = context.wrap_socket(raw, server_hostname=hostname)
            wrapped.settimeout(timeout)
            return wrapped
        return raw
    except Exception:
        raw.close()
        raise

def _request_public(
    url: str,
    method: str = "GET",
    timeout: float = REQUEST_TIMEOUT,
    max_bytes: int = MAX_RESPONSE_BYTES,
) -> dict[str, Any]:
    scheme, hostname, port, _ = _validate_target(url)
    parsed = urlsplit(url)
    addresses = _resolve_public_addresses(hostname)
    path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
    if parsed.query:
        path += "?" + quote(parsed.query, safe="=&%:@!$'()*+,-._~")
    if not path.startswith("/") or "\r" in path or "\n" in path:
        raise ValueError("Cible HTTP invalide.")
    last_error: Exception | None = None
    for address in addresses[:4]:
        sock = None
        try:
            sock = _connection_for_address(address, port, hostname, scheme, timeout)
            host_header = hostname
            request = (
                f"{method} {path} HTTP/1.1\r\n"
                f"Host: {host_header}\r\n"
                "User-Agent: WebScope-Audit/3.1 (+authorized-security-assessment)\r\n"
                "Accept: text/html,application/xhtml+xml,application/json,*/*;q=0.5\r\n"
                "Accept-Encoding: identity\r\n"
                "Connection: close\r\n\r\n"
            )
            sock.sendall(request.encode("ascii"))
            response = HTTPResponse(sock)
            response.begin()
            headers = {key.lower(): value for key, value in response.getheaders()}
            body = response.read(max_bytes + 1) if method != "HEAD" else b""
            tls = None
            if scheme == "https":
                cert = sock.getpeercert()
                tls = {
                    "version": sock.version(),
                    "cipher": (sock.cipher() or [None])[0],
                    "subject": cert.get("subject", ()),
                    "issuer": cert.get("issuer", ()),
                    "not_after": cert.get("notAfter"),
                }
            result = {
                "ok": True,
                "status_code": response.status,
                "reason": response.reason,
                "url": url,
                "ip": address,
                "headers": headers,
                "content_type": headers.get("content-type", "unknown"),
                "content_length": headers.get("content-length"),
                "body": body[:max_bytes],
                "body_truncated": len(body) > max_bytes,
                "tls": tls,
            }
            response.close()
            return result
        except (OSError, ssl.SSLError, TimeoutError, ValueError) as exc:
            last_error = exc
            if sock is not None:
                sock.close()
    raise RuntimeError(f"Connexion publique impossible pour {hostname}: {type(last_error).__name__ if last_error else 'unknown'}")

def _same_origin_redirect(current_url: str, location: str) -> str | None:
    candidate = urljoin(current_url, location)
    current = urlsplit(current_url)
    target = urlsplit(candidate)
    if target.hostname is None or target.hostname.lower().rstrip(".") != current.hostname.lower().rstrip("."):
        return None
    if target.scheme.lower() not in {"http", "https"}:
        return None
    if current.scheme == "https" and target.scheme == "http":
        return None
    return candidate

def _inspect_subdomains(hostname: str) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    for prefix in COMMON_SUBDOMAINS:
        candidate = f"{prefix}.{hostname}"
        try:
            addresses = _resolve_public_addresses(candidate)
        except (ValueError, RuntimeError):
            continue
        found.append({"name": candidate, "ip": ", ".join(addresses[:2]), "status": "dns_resolved"})
        if len(found) >= MAX_SUBDOMAINS:
            break
    return found

def _add_signal(signals: list[dict], code: str, label: str, points: int,
                severity: str, explanation: str) -> None:
    signals.append({
        "code": code, "label": label, "points": points,
        "severity": severity, "explanation": explanation,
    })

def run_scan(target_url: str, authorized_scope: bool = False) -> dict[str, Any]:
    """Run a bounded, public-only HTTP audit. Never downloads linked files or follows off-origin redirects."""
    if not authorized_scope:
        raise ValueError("Confirmez que vous êtes autorisé à auditer cette cible.")
    scheme, hostname, _, normalized_url = _validate_target(target_url)
    # Run local URL heuristics first, without network access.
    url_signals = analyze_url(normalized_url)["signals"]
    signals: list[dict] = list(url_signals)
    findings: list[dict] = []
    urls: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    dns_records: list[dict[str, str]] = []
    errors: list[str] = []
    redirect_chain: list[str] = []

    addresses = _resolve_public_addresses(hostname)
    for address in addresses:
        dns_records.append({"type": "AAAA" if ":" in address else "A", "value": address})

    current_url = normalized_url
    page: dict[str, Any] | None = None
    for redirect_index in range(4):
        page = _request_public(current_url, method="GET", max_bytes=MAX_RESPONSE_BYTES)
        redirect_chain.append(current_url)
        if page["status_code"] not in {301, 302, 303, 307, 308}:
            break
        location = page["headers"].get("location")
        if not location:
            break
        next_url = _same_origin_redirect(current_url, location)
        if not next_url:
            _add_signal(
                signals, "CROSS_ORIGIN_REDIRECT", "Redirection vers un autre domaine", 12, "medium",
                "La redirection sort du domaine autorisé ; elle n'a pas été suivie.",
            )
            break
        current_url = next_url
    if page is None:
        raise RuntimeError("Le scanner n'a pas pu récupérer la réponse HTTP.")
    scheme = urlsplit(current_url).scheme.lower()
    status_code = int(page["status_code"])
    if status_code in {301, 302, 303, 307, 308}:
        _add_signal(signals, "REDIRECT_LIMIT_REACHED", "Limite de redirections atteinte", 5, "low",
                    "Le scanner a atteint sa limite de redirections même sur la même origine.")
    headers = page["headers"]
    if status_code >= 500:
        _add_signal(signals, "HTTP_SERVER_ERROR", "Erreur HTTP côté serveur", 12, "medium",
                    f"Le serveur renvoie HTTP {status_code}.")
    elif status_code >= 400:
        _add_signal(signals, "HTTP_CLIENT_ERROR", "Réponse HTTP d'erreur", 5, "low",
                    f"La ressource racine renvoie HTTP {status_code}.")
    if scheme == "http":
        _add_signal(signals, "HTTP_NO_TLS", "Cible consultée en HTTP", 10, "medium",
                    "La requête initiale utilise HTTP sans chiffrement de transport.")

    security_headers = (
        ("strict-transport-security", "HSTS absent", 8, "medium"),
        ("content-security-policy", "Content-Security-Policy absent", 8, "medium"),
        ("x-content-type-options", "X-Content-Type-Options absent", 4, "low"),
        ("x-frame-options", "Protection anti-clickjacking absente", 4, "low"),
        ("referrer-policy", "Referrer-Policy absent", 3, "low"),
    )
    for header_name, label, points, severity in security_headers:
        if header_name not in headers and (header_name != "strict-transport-security" or current_url.startswith("https://")):
            _add_signal(signals, "MISSING_" + header_name.upper().replace("-", "_"),
                        label, points, severity,
                        f"L'en-tête HTTP {header_name} n'a pas été observé sur la réponse racine.")
    server_header = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    if re.search(r"/[0-9]+(?:\.[0-9]+){1,3}", server_header + " " + powered_by):
        _add_signal(signals, "TECH_VERSION_DISCLOSURE", "Version technologique divulguée", 5, "low",
                    "Un en-tête HTTP divulgue potentiellement une version logicielle.")

    content_type = page["content_type"].lower()
    body = page["body"]
    if "html" in content_type and body:
        soup = BeautifulSoup(body, "html.parser")
        seen: set[str] = set()
        for tag in soup.find_all(["a", "link", "script", "img", "source", "form"]):
            value = tag.get("href") or tag.get("src") or tag.get("action")
            if not value:
                continue
            absolute = urljoin(current_url, value)
            parsed_link = urlsplit(absolute)
            if parsed_link.scheme not in {"http", "https"}:
                continue
            if parsed_link.hostname and parsed_link.hostname.lower() == hostname and absolute not in seen:
                seen.add(absolute)
                urls.append({
                    "url": absolute[:2048], "source": "html_reference",
                    "status_code": 0, "depth": 1,
                })
        for index, candidate_path in enumerate(COMMON_PATHS[:MAX_PATH_PROBES]):
            probe_url = f"{scheme}://{hostname}{candidate_path}"
            try:
                probe = _request_public(probe_url, method="HEAD", max_bytes=0)
                if probe["status_code"] == 200 and candidate_path in SENSITIVE_PATHS:
                    _add_signal(
                        signals, "SENSITIVE_PATH_EXPOSED", "Chemin sensible accessible",
                        25, "high", f"Le chemin {candidate_path} répond HTTP 200 à une requête HEAD.",
                    )
                elif probe["status_code"] in {401, 403} and candidate_path in SENSITIVE_PATHS:
                    _add_signal(
                        signals, "SENSITIVE_PATH_RESTRICTED", "Chemin sensible protégé",
                        2, "low", f"Le chemin {candidate_path} existe ou est filtré (HTTP {probe['status_code']}).",
                    )
            except (ValueError, RuntimeError):
                errors.append(f"Probe HEAD non concluante pour {candidate_path}.")
    else:
        _add_signal(signals, "NON_HTML_ROOT", "Ressource racine non HTML", 1, "low",
                    f"Le type de contenu racine est {content_type}.")

    tls_info = page.get("tls")
    if scheme == "http":
        try:
            https_probe = _request_public(f"https://{hostname}/", method="HEAD", max_bytes=0)
            tls_info = https_probe.get("tls")
        except (ValueError, RuntimeError) as exc:
            _add_signal(signals, "TLS_UNAVAILABLE", "HTTPS/TLS non vérifiable", 15, "medium",
                        "La connexion TLS publique n'a pas pu être établie ou son certificat n'a pas été validé.")
            errors.append(f"Vérification TLS : {type(exc).__name__}.")
    elif not tls_info:
        _add_signal(signals, "TLS_UNAVAILABLE", "HTTPS/TLS non vérifiable", 15, "medium",
                    "Aucune information TLS validée n'a été récupérée.")

    subdomains = _inspect_subdomains(hostname)
    if subdomains:
        _add_signal(signals, "PUBLIC_SUBDOMAINS_FOUND", "Sous-domaines publics détectés", 2, "low",
                    f"{len(subdomains)} sous-domaines répondent à une résolution DNS publique.")

    score = min(100, sum(item["points"] for item in signals))
    level = "critical" if score >= 75 else "high" if score >= 50 else "medium" if score >= 25 else "low"
    findings = [{
        "category": "web_audit",
        "title": item["label"],
        "severity": item["severity"],
        "description": item["explanation"],
        "evidence": item["code"],
    } for item in signals]
    summary = (
        f"Audit web autorisé terminé pour {hostname}: risque {level} ({score}/100), "
        f"{len(signals)} signal(s), {len(subdomains)} sous-domaine(s) DNS, "
        f"{len(urls)} référence(s) internes. Les fichiers référencés n'ont pas été téléchargés."
    )
    return {
        "target_url": normalized_url,
        "final_url": current_url,
        "status_code": status_code,
        "hostname": hostname,
        "dns_records": dns_records,
        "subdomains": subdomains,
        "urls": urls[:MAX_URLS_TO_RETURN],
        "files": files,
        "findings": findings,
        "signals": signals,
        "summary": summary,
        "risk_score": score,
        "risk_level": level,
        "tls": tls_info or {"status": "not_verified"},
        "errors": errors,
        "redirect_chain": redirect_chain,
        "network_access": "public_dns_and_http_https_only",
        "limits": {
            "ports": [80, 443],
            "max_redirects": 3,
            "max_response_bytes": MAX_RESPONSE_BYTES,
            "max_path_probes": MAX_PATH_PROBES,
            "files_downloaded": False,
            "subdomains_connected": False,
            "cross_origin_redirects_followed": False,
        },
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }
