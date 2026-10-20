# WebScope Audit V2

WebScope Audit V2 est une version améliorée d'un outil Python 3.11 de contrôle public d'un site web autorisé. Il collecte les informations DNS, HTTP/HTTPS, TLS, détecte les technologies publiquement visibles et génère un rapport HTML et JSON exploitable.

## Fonctionnalités V2

- Validation stricte des URL publiques.
- Normalisation des cibles et contrôle des redirections.
- Analyse DNS : A, AAAA, CNAME, MX, NS, TXT.
- Analyse HTTP/HTTPS : statut, headers, final URL, redirections, temps de réponse.
- Analyse TLS : subject, issuer, SAN, validité, erreurs de connexion.
- Détection prudente des technologies via headers et HTML public.
- Rapport HTML structuré et export JSON.
- Historique SQLite des analyses.
- Interface CLI et interface graphique Tkinter.

## Limites connues

- Le périmètre est limité à un site public autorisé.
- La V2 ne couvre pas les sous-domaines massifs, les ports non web, les téléchargements massifs, ni les tentatives d'exploitation.
- Les technologies sont détectées uniquement à partir de données publiques et sans inventer de version logicielle.
- Aucune désactivation de validation TLS n'est effectuée.

## Installation sous Windows 10/11

1. Installer Python 3.11 ou plus récent.
2. Ouvrir PowerShell dans le dossier du projet.
3. Créer un environnement virtuel :

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

4. Installer les dépendances :

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

5. Lancer l'application :

```powershell
python main.py --gui
```

ou :

```powershell
python main.py https://example.com --output-dir reports
```

## Utilisation

```powershell
python main.py https://example.com --output-dir reports
python main.py https://example.com --no-dns --no-tls
```

## Structure du projet

```text
webscope_audit/
  app/
  templates/
  reports/
  tests/
main.py
requirements.txt
README.md
```

## Exécution des tests

```powershell
pytest -q
```

## Rapport d'exemple

Un fichier HTML et JSON est fourni dans le dossier `reports/` comme exemple fictif. Il est clair que ce n'est pas un scan réel.

## Sécurité

- Validation de la cible publique uniquement.
- Redirections limitées et contrôlées.
- Interdiction de contourner l'authentification ou les mécanismes de sécurité.
- Validation TLS non désactivée.
