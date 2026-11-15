from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from hashlib import sha256
from urllib.parse import urlsplit

MAX_URL_LENGTH = 2048
SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "cutt.ly", "is.gd", "ow.ly", "buff.ly"}
BRAND_LABELS = ("wave", "orange", "mtn", "moov", "visa", "mastercard")
URL_KEYWORDS = ("login", "verify", "verification", "wallet", "otp", "secure", "support", "update", "bonus", "claim")
FILE_INDICATORS = (
    (b"accessibilityservice", "Android Accessibility Service reference", 18),
    (b"android.permission.read_sms", "Android READ_SMS permission reference", 20),
    (b"android.permission.receive_sms", "Android RECEIVE_SMS permission reference", 20),
    (b"android.permission.send_sms", "Android SEND_SMS permission reference", 20),
    (b"deviceadminreceiver", "Android Device Administrator reference", 15),
    (b"dexclassloader", "Dynamic Android code-loading reference", 15),
    (b"powershell -enc", "Encoded PowerShell command reference", 18),
    (b"mshta.exe", "MSHTA execution reference", 15),
    (b"rundll32", "Rundll32 execution reference", 12),
    (b"regsvr32", "Regsvr32 execution reference", 12),
    (b"cmd.exe /c", "Windows command-shell reference", 10),
    (b"createRemoteThread", "Remote-thread creation API reference", 15),
    (b"setwindowshookex", "Windows hook API reference", 10),
)

def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())

def _edit_distance(left: str, right: str) -> int:
    previous = list(range(len(right) + 1))
    for i, char_left in enumerate(left, 1):
        current = [i]
        for j, char_right in enumerate(right, 1):
            current.append(min(current[-1] + 1, previous[j] + 1, previous[j - 1] + (char_left != char_right)))
        previous = current
    return previous[-1]

def analyze_url(raw_url: str) -> dict:
    """Analyze URL syntax only. This function deliberately performs no DNS lookup or HTTP request."""
    if not raw_url or len(raw_url) > MAX_URL_LENGTH:
        raise ValueError("URL absente ou trop longue (2048 caractères maximum).")
    if any(ord(char) < 32 for char in raw_url) or "\\" in raw_url:
        raise ValueError("URL contenant des caractères de contrôle ou des antislashs.")
    try:
        parsed = urlsplit(raw_url.strip())
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL mal formée.") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Seules les URL HTTP(S) complètes sont acceptées.")
    hostname_raw = parsed.hostname.rstrip(".")
    try:
        hostname = hostname_raw.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Nom d’hôte IDN invalide.") from exc

    signals = []
    score = 0
    def add(code: str, label: str, points: int, explanation: str, severity: str = "medium") -> None:
        nonlocal score
        score += points
        signals.append({"code": code, "label": label, "points": points, "severity": severity, "explanation": explanation})

    if parsed.username is not None or parsed.password is not None:
        add("URL_USERINFO", "Identifiants intégrés dans l’URL", 30, "La partie avant @ peut masquer le véritable domaine.", "high")
    if hostname.startswith("xn--") or ".xn--" in hostname:
        add("IDN_PUNYCODE", "Nom de domaine internationalisé", 15, "Un domaine punycode peut être légitime, mais facilite aussi les homographes.", "medium")
    try:
        address = ipaddress.ip_address(hostname)
        if not address.is_global:
            add("NON_PUBLIC_IP", "Adresse IP non publique", 35, "L’URL pointe vers une adresse IP privée ou spéciale. Ne pas l’ouvrir depuis un poste métier.", "critical")
        else:
            add("IP_LITERAL", "Adresse IP utilisée comme hôte", 15, "Les campagnes de phishing utilisent parfois directement des adresses IP.", "medium")
    except ValueError:
        labels = hostname.split(".")
        if len(labels) > 4:
            add("DEEP_SUBDOMAIN", "Nom de domaine très imbriqué", 10, "Le nombre élevé de sous-domaines peut servir à imiter une marque.", "low")
        if _entropy(labels[-2] if len(labels) >= 2 else hostname) > 3.6:
            add("HIGH_DOMAIN_ENTROPY", "Nom de domaine à forte entropie", 10, "Le libellé paraît aléatoire ; à confronter aux données de réputation.", "low")
        for label in labels:
            if label in {"www", "com", "net", "org", "co", "ci"}:
                continue
            for brand in BRAND_LABELS:
                if len(label) >= 4 and label != brand and _edit_distance(label, brand) <= 1:
                    add("BRAND_LOOKALIKE", "Proximité avec une marque financière", 25, f"Le libellé « {label} » ressemble à « {brand} » sans être identique.", "high")
                    break
            if any(token in label for token in URL_KEYWORDS):
                add("SENSITIVE_KEYWORD", "Mot-clé sensible dans le domaine", 5, f"Le domaine contient un terme courant dans les leurres de connexion : {label}.", "low")
                break

    if hostname in SHORTENERS:
        add("URL_SHORTENER", "Raccourcisseur d’URL", 20, "La destination réelle est masquée et doit être vérifiée dans un environnement isolé.", "high")
    if parsed.scheme.lower() == "http":
        add("HTTP_CLEAR_TEXT", "Connexion sans HTTPS", 8, "Le transport HTTP ne protège pas les données en transit.", "medium")
    if port not in (None, 80, 443):
        add("UNUSUAL_PORT", "Port HTTP(S) inhabituel", 10, "Un service web sur un port non standard mérite une vérification.", "low")
    if len(parsed.query) > 500 or len(parsed.query.split("&")) > 12:
        add("COMPLEX_QUERY", "Paramètres d’URL nombreux ou volumineux", 8, "Une URL très chargée peut dissimuler des paramètres de redirection ou de suivi.")
    score = min(score, 100)
    level = "critical" if score >= 75 else "high" if score >= 50 else "medium" if score >= 25 else "low"
    return {
        "submitted_url": raw_url,
        "normalized_host": hostname,
        "risk_score": score,
        "risk_level": level,
        "signals": signals,
        "network_access": "none",
        "recommendation": "Ne pas cliquer. Vérifier le domaine par un canal indépendant et utiliser une passerelle de sécurité/reputation approuvée.",
        "limitations": "Analyse syntaxique heuristique uniquement : aucune consultation DNS, réputation externe, navigation, ni verdict antivirus.",
    }

def inspect_file_bytes(content: bytes) -> dict:
    """Static-only triage. Never executes, imports, extracts, or detonates the submitted sample."""
    if not content:
        raise ValueError("Le fichier est vide.")
    sample = content[:25_000_000]
    lower = sample.lower()
    if sample.startswith(b"MZ"):
        file_type = "windows_pe"
    elif sample.startswith(b"\x7fELF"):
        file_type = "elf"
    elif sample.startswith(b"%PDF-"):
        file_type = "pdf"
    elif sample.startswith(b"PK\x03\x04"):
        file_type = "zip_or_apk"
    elif sample.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        file_type = "ole_compound_document"
    elif sample[:4] in {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}:
        file_type = "mach_o"
    else:
        file_type = "unknown_or_text"

    matches = []
    for marker, label, points in FILE_INDICATORS:
        if marker.lower() in lower:
            matches.append({"indicator": label, "points": points})
    sha256_digest = sha256(sample).hexdigest()
    score = min(sum(item["points"] for item in matches), 100)
    level = "high" if score >= 40 else "medium" if score >= 15 else "low"
    return {
        "sha256": sha256_digest,
        "size_bytes": len(content),
        "file_type": file_type,
        "static_indicators": matches,
        "risk_score": score,
        "risk_level": level,
        "disposition": "quarantined_manual_review",
        "execution_performed": False,
        "archive_extraction_performed": False,
        "network_access_performed": False,
        "verdict": "suspicious_static_indicators_found" if matches else "no_known_static_indicators_found",
        "limitations": "Absence d’indicateurs ne signifie pas absence de malware. Analyse statique heuristique uniquement ; aucun moteur AV/YARA ni sandbox dynamique n’est configuré.",
    }
