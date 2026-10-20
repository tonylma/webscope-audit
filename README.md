# WebScope Audit Premium

WebScope Audit est un outil de reconnaissance et d’audit de surface d’attaque publique, destiné à analyser un domaine ou une URL publique et à produire un rapport exploitable.

## Stack

- Backend: Python + FastAPI
- Base de données: PostgreSQL
- Caching/Broker: Redis
- Workers: Celery
- Frontend: React + TypeScript + Vite
- Déploiement: Docker Compose

## Démarrage rapide

```bash
docker compose up --build
```

## Services

- API Backend: http://localhost:8000
- Frontend: http://localhost:5173
- PostgreSQL: localhost:5432
- Redis: localhost:6379

## Fonctionnalités MVP couvertes

- Validation d’URL et normalisation
- Analyse DNS et découverte de sous-domaines
- Analyse HTTP et redirections
- Analyse TLS / certificat
- Découverte d’URLs et crawl limité
- Téléchargement public contrôlé
- Génération de rapport HTML/JSON
- Historique de scans
- Dashboard professionnel

## Sécurité

- Timeouts stricts
- Limite de profondeur de crawl
- Limite de fichiers et tailles
- Analyse uniquement sur périmètre public et autorisé
