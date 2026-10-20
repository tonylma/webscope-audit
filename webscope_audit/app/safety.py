from urllib.parse import urlsplit, urlunsplit
import ipaddress

ALLOWED_SCHEMES = {"http", "https"}


def normalize_url(value: str) -> str:
    text = (value or "").strip()
    if not text:
        raise ValueError("La cible est vide.")

    if "://" not in text:
        text = "https://" + text

    split = urlsplit(text)
    if split.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError("Seules les URL HTTP et HTTPS sont acceptées.")

    hostname = split.hostname or ""
    if not hostname:
        raise ValueError("L'URL ne contient pas d'hôte valide.")

    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        ip = None

    if ip is not None and (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved):
        raise ValueError("L'URL cible ne doit pas pointer vers un hôte interne ou privé.")

    netloc = hostname if split.port in (None, 80, 443) else f"{hostname}:{split.port}"
    normalized = urlunsplit((split.scheme.lower(), netloc, split.path or "/", split.query, split.fragment))
    if normalized.endswith("/") and split.path == "":
        return normalized
    return normalized.rstrip("/") if not split.path else normalized


def validate_url(value: str) -> tuple[bool, str]:
    try:
        url = normalize_url(value)
    except ValueError as exc:
        return False, str(exc)

    hostname = urlsplit(url).hostname or ""
    if not hostname:
        return False, "URL invalide : hôte manquant."

    if hostname in {"localhost", "127.0.0.1"}:
        return False, "La cible doit être un site public, pas un hôte local."

    return True, url


def validate_redirect_destination(current_url: str, redirect_url: str, seen_hosts: set[str]) -> bool:
    try:
        current = urlsplit(current_url)
        redirect = urlsplit(redirect_url)
    except ValueError:
        return False

    if redirect.scheme not in ALLOWED_SCHEMES:
        return False

    host = (redirect.hostname or "").lower()
    if not host:
        return False

    if current.hostname and current.hostname.lower() == host:
        return True

    if host not in seen_hosts:
        seen_hosts.add(host)
    return True
