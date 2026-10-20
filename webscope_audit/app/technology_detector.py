from __future__ import annotations

from typing import Any

from bs4 import BeautifulSoup


def detect_technologies(headers: dict[str, Any], html_text: str) -> dict[str, list[dict[str, str]]]:
    confirmed: list[dict[str, str]] = []
    suspected: list[dict[str, str]] = []

    server = str(headers.get("server", "")).lower()
    if "nginx" in server:
        confirmed.append({"name": "nginx", "source": "header", "confidence": "confirmed"})
    if "apache" in server:
        confirmed.append({"name": "apache", "source": "header", "confidence": "confirmed"})

    powered_by = str(headers.get("x-powered-by", "")).lower()
    if powered_by:
        confirmed.append({"name": powered_by, "source": "header", "confidence": "confirmed"})

    for header_name in ("x-generator", "generator"):
        value = headers.get(header_name)
        if value:
            confirmed.append({"name": str(value), "source": "header", "confidence": "confirmed"})

    soup = BeautifulSoup(html_text or "", "html.parser")
    if soup.find("script", src=True):
        scripts = [str(script.get("src", "")).lower() for script in soup.find_all("script", src=True)]
        for script in scripts:
            if "jquery" in script:
                confirmed.append({"name": "jquery", "source": "html", "confidence": "confirmed"})
            if "bootstrap" in script:
                confirmed.append({"name": "bootstrap", "source": "html", "confidence": "confirmed"})

    generator_meta = soup.find("meta", attrs={"name": "generator"})
    if generator_meta:
        generator_value = str(generator_meta.get("content", "")).strip()
        if generator_value:
            suspected.append({"name": generator_value, "source": "html", "confidence": "suspected"})

    return {"confirmed": confirmed, "suspected": suspected}
