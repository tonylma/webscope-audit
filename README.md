# WebScope Audit V4

WebScope Audit V4 est une version plus complète d'un outil Python 3.11 pour l'analyse publique d'un site web autorisé, avec génération de rapports HTML, Word et PDF améliorés.

## Ce qui distingue la V4

- Analyse publique plus robuste et plus détaillée.
- Validation stricte des URL et des redirections.
- DNS, sous-domaines, ports, technologies et crawl léger.
- Export de rapport HTML, JSON, Word (.docx) et PDF.
- Présentation visuelle améliorée avec couleurs, cartes d'informations et sections structurées.
- Contrôles de sécurité et limites explicites du périmètre.

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

## Sorties générées

- HTML : rapport détaillé, coloré et lisible.
- JSON : données brutes structurées.
- DOCX : document Word prêt à partager.
- PDF : export visuel pour présentation.

## Sécurité

- Périmètre public uniquement.
- Validation TLS active.
- Limitation des redirections, du nombre de requêtes et du volume de réponse.
- Aucune tentative d'exploitation, de contournement ou d'accès non autorisé.
