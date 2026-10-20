from __future__ import annotations

import argparse
from pathlib import Path

from .config import AppConfig
from .report_generator import write_report_files
from .scanner import SiteScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="WebScope Audit V3")
    parser.add_argument("target", nargs="?", default="https://example.com", help="URL publique à analyser")
    parser.add_argument("--output-dir", default="reports", help="Dossier de sortie pour les rapports")
    parser.add_argument("--timeout", type=float, default=10.0, help="Délai d'attente en secondes")
    parser.add_argument("--max-redirects", type=int, default=5, help="Nombre maximal de redirections")
    parser.add_argument("--db-path", default="reports/webscope_audit.db", help="Chemin de la base SQLite")
    parser.add_argument("--max-pages", type=int, default=5, help="Nombre de pages à explorer")
    parser.add_argument("--max-subdomains", type=int, default=20, help="Nombre maximal de sous-domaines à tester")
    parser.add_argument("--ports", nargs="*", type=int, default=[80, 443, 8080, 8443], help="Ports à tester")
    parser.add_argument("--no-dns", action="store_true", help="Désactiver l'analyse DNS")
    parser.add_argument("--no-http", action="store_true", help="Désactiver l'analyse HTTP")
    parser.add_argument("--no-tls", action="store_true", help="Désactiver l'analyse TLS")
    parser.add_argument("--no-tech", action="store_true", help="Désactiver la détection de technologies")
    parser.add_argument("--no-port-scan", action="store_true", help="Désactiver le scan de ports")
    parser.add_argument("--no-subdomain-scan", action="store_true", help="Désactiver le scan de sous-domaines")
    parser.add_argument("--no-crawl", action="store_true", help="Désactiver l'exploration de pages")
    parser.add_argument("--gui", action="store_true", help="Lancer l'interface graphique Tkinter")
    return parser


def launch_gui() -> None:
    import tkinter as tk
    from tkinter import ttk

    root = tk.Tk()
    root.title("WebScope Audit V3")
    root.geometry("780x520")

    frame = ttk.Frame(root, padding=12)
    frame.pack(fill="both", expand=True)

    ttk.Label(frame, text="Cible autorisée", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w")
    target_var = tk.StringVar(value="https://example.com")
    ttk.Entry(frame, textvariable=target_var, width=70).grid(row=1, column=0, sticky="ew")

    ttk.Label(frame, text="Dossier de sortie", font=("Segoe UI", 10, "bold")).grid(row=2, column=0, sticky="w", pady=(12, 0))
    output_var = tk.StringVar(value="reports")
    ttk.Entry(frame, textvariable=output_var, width=70).grid(row=3, column=0, sticky="ew")

    summary = tk.Text(frame, height=12, width=80)
    summary.grid(row=4, column=0, sticky="nsew", pady=(12, 0))

    def run_analysis() -> None:
        config = AppConfig(
            target_url=target_var.get(),
            output_dir=output_var.get(),
            timeout=10.0,
            max_redirects=5,
            max_response_bytes=250000,
            max_pages=5,
            max_subdomains=20,
            allowed_ports=tuple([80, 443, 8080, 8443]),
        )
        result = SiteScanner(config=config).analyze(target_var.get())
        html_path, json_path = write_report_files(result, output_var.get())
        summary.delete("1.0", tk.END)
        summary.insert("end", f"Analyse terminée\nHTML: {html_path}\nJSON: {json_path}\n\n")
        summary.insert("end", f"Cible: {result['target']}\n")
        summary.insert("end", f"HTTP: {result.get('http', {}).get('status')}")

    ttk.Button(frame, text="Lancer l'analyse", command=run_analysis).grid(row=5, column=0, sticky="w", pady=(12, 0))
    frame.columnconfigure(0, weight=1)
    frame.rowconfigure(4, weight=1)
    root.mainloop()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.gui:
        launch_gui()
        return 0

    config = AppConfig(
        target_url=args.target,
        output_dir=args.output_dir,
        timeout=args.timeout,
        max_redirects=args.max_redirects,
        db_path=args.db_path,
        max_pages=args.max_pages,
        max_subdomains=args.max_subdomains,
        allowed_ports=tuple(args.ports),
        enable_port_scan=not args.no_port_scan,
        enable_subdomain_scan=not args.no_subdomain_scan,
        enable_crawl=not args.no_crawl,
        include_dns=not args.no_dns,
        include_http=not args.no_http,
        include_tls=not args.no_tls,
        include_technologies=not args.no_tech,
    )

    result = SiteScanner(config=config).analyze(args.target)
    html_path, json_path = write_report_files(result, args.output_dir)
    print(f"Analyse terminée. HTML: {html_path}\nJSON: {json_path}")
    return 0
