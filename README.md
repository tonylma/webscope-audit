# WebScope Audit Premium

WebScope Audit est une plateforme d'analyse technique, de sécurité et de découverte de surface d'attaque d'un domaine ou d'une URL publique. Le projet vise à fournir une vue fiable de l'exposition technique d'un site en combinant validation URL, DNS, HTTP, TLS, redirections, sous-domaines, crawling, services exposés, fichiers publics et génération de rapport HTML/JSON.

## Stack technique

- Backend: Python 3.11 + FastAPI
- Base de données: PostgreSQL
- Cache / broker: Redis
- Workers: Celery
- Frontend: React + TypeScript + Vite
- Analyse réseau: Python + nmap
- Rapports: HTML et JSON
- Déploiement: Docker / Docker Compose

## Architecture

- `backend/`: API FastAPI, worker Celery, moteur de scan, modèles de données
- `frontend/`: dashboard React/TypeScript
- `infra/`: utilitaires d'infrastructure et scripts de déploiement
- `docs/`: architecture, API et documentation produit
- `reports/`: exports de rapports générés

## Fonctionnalités MVP

- Validation et normalisation d'URL
- Résolution DNS et collecte d'informations de connectivité
- Analyse HTTP et détection de redirections
- Validation TLS / certificat
- Découverte de sous-domaines
- Discovery d'URL et crawl de pages publiques
- Téléchargement limité de fichiers publics
- Génération de rapports HTML et JSON
- Historique de scans
- API REST et dashboard moderne

## Démarrage rapide

```bash
docker compose up --build
```

Accès:

- API: http://localhost:8000
- Frontend: http://localhost:5173
- PostgreSQL: localhost:5432
- Redis: localhost:6379

## Commandes dev

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

```bash
cd frontend
npm install
npm run dev
```

## Sécurité et cadre légal

- Limiter les analyses aux domaines publics et autorisés.
- Respecter les timeouts et la limite de profondeur de crawl.
- Contrôler les tailles des fichiers téléchargés.
- Ne pas explorer plus que nécessaire.

## Auteurs

Projet conçu pour l'audit public de surface d'attaque et la reconnaissance technique légitime.
