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

    for value in (headers.get("x-generator"), headers.get("generator")):
        if value:
            confirmed.append({"name": str(value), "source": "header", "confidence": "confirmed"})

    soup = BeautifulSoup(html_text or "", "html.parser")
    if soup.find("script", src=True):
        sources = [str(script.get("src","")).lower() for script in soup.find_all("script", src=True)]
        for source in sources:
            if "jquery" in source:
                confirmed.append({"name": "jquery", "source": "html", "confidence": "confirmed"})
            if "bootstrap" in source:
                confirmed.append({"name": "bootstrap", "source": "html", "confidence": "confirmed"})

    if soup.find("meta", attrs={"name": "generator"}):
        generator = str(soup.find("meta", attrs={"name": "generator"}).get("content", "")).strip()
        if generator:
            suspected.append({"name": generator, "source": "html", "confidence": "suspected"})

    return {"confirmed": confirmed, "suspected": suspected}
