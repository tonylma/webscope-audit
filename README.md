# WebScope Audit V5

WebScope Audit V5 est une version plus professionnelle d'un outil Python 3.11 pour l'analyse publique d'un site web autorisé, conçu pour produire des rapports structurés, lisibles et exploitables pour une remise client, un partenaire ou une présentation investisseur.

## Objectif de la V5

- Produire un rapport d'audit public de qualité professionnelle.
- Rendre la synthèse exploitable à partir d'un score global, d'un tableau de risques et d'une priorisation claire des recommandations.
- Améliorer le rendu visuel et la lisibilité des exports HTML, Word et PDF.
- Maintenir un cadre légal, éthique et public : périmètre ouvert et autorisé uniquement.

## Fonctionnalités renforcées

- Analyse publique stricte des URL, redirections, DNS, HTTP, TLS, technologies, ports et sous-domaines.
- Score global synthétique.
- Tableau de risque détaillé par niveau.
- Recommandations hiérarchisées par priorité.
- Présentation HTML modernisée et plus professionnelle.
- Export Word et PDF adaptés à une remise client.
- Documentation de projet plus claire et plus orientée produit.

## Installation

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Utilisation

```powershell
python main.py https://example.com --output-dir reports
python main.py https://example.com --output-dir reports --no-docx --no-pdf
```

## Sorties produites

- HTML : rapport visuellement structuré et prêt à l'usage.
- JSON : données d'analyse exposées en structure exploitable.
- DOCX : document Word pour une remise client ou une synthèse métier.
- PDF : export plus lisible pour la diffusion externe.

## Sécurité et cadre légal

- Analyse limitée aux services publics et autorisés.
- Validation stricte des cibles et des redirections.
- Aucune exploitation ni contournement de mécanismes de sécurité.
- Limitation du périmètre et du volume de données collectées.
