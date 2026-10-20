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

    host = split.hostname or ""
    if not host:
        raise ValueError("L'URL ne contient pas d'hôte valide.")

    port = split.port or (443 if split.scheme.lower() == "https" else 80)
    netloc = host if port in (80, 443) else f"{host}:{port}"
    normalized = urlunsplit((split.scheme.lower(), netloc, split.path or "/", split.query, split.fragment))
    return normalized.rstrip("/") + ("/" if split.path == "" else "") if split.path == "" else normalized


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

    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        ip = None

    if ip is not None and (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved):
        return False, "L'URL cible ne doit pas pointer vers un hôte interne ou privé."

    return True, url


def validate_redirect_destination(current_url: str, redirect_url: str, seen_hosts: set[str]) -> bool:
    from urllib.parse import urlsplit

    try:
        current = urlsplit(current_url)
        redirect = urlsplit(redirect_url)
    except ValueError:
        return False

    if redirect.scheme not in ALLOWED_SCHEMES:
        return False

    current_host = (current.hostname or "").lower()
    redirect_host = (redirect.hostname or "").lower()
    if not redirect_host:
        return False

    if current_host and redirect_host not in seen_hosts and redirect_host != current_host:
        seen_hosts.add(redirect_host)

    return True
