# WebScope Audit Premium

WebScope Audit est une plateforme d’audit public de surface d’attaque et de reconnaissance web. Elle permet d’analyser un site ou un domaine public, d’extraire la surface exposée, détecter les sous-domaines, identifier les chemins visibles, et produire un rapport exploitable en HTML/JSON.

Ce dépôt contient la version finale de production du projet, organisée autour de :
- backend FastAPI
- workers Celery + Redis
- PostgreSQL
- frontend React + TypeScript
- moteur de scan Python avec DNS, HTTP, TLS, sous-domaines, crawl et rapport

## Démarrage rapide

```bash
docker compose up --build
```

Puis ouvrez :
- Frontend : http://localhost:5173
- API : http://localhost:8000/docs
- PostgreSQL : localhost:5432
- Redis : localhost:6379

## Fonctionnalités

- validation et normalisation d’URL
- résolution DNS et découverte de sous-domaines
- analyse HTTP et redirections
- détection de chemins publics sensibles
- crawl HTML avec extraction d’URL
- téléchargement contrôlé de fichiers publics
- génération de résumés de risque
- historique de scans
- dashboard moderne
- génération de rapport HTML/JSON

## Stack

- Python 3.11
- FastAPI
- Celery + Redis
- PostgreSQL
- React + TypeScript + Vite
- Docker Compose
- Nmap (via image backend)

## Structure du projet final

- `backend/` : API, moteur de scan et services métier
- `frontend/` : interface utilisateur
- `infra/postgres/` : script d’initialisation PostgreSQL
- `docker-compose.yml` : orchestration locale
- `Makefile` : commandes de lancement

## Sécurité et cadre légal

- La plateforme est conçue pour l’audit public et autorisé.
- Les scans sont limités par timeout, taille et profondeur.
- Les requêtes ne doivent pas dépasser le périmètre de test autorisé.

## Exemple de scan

```bash
curl -X POST http://localhost:8000/scan \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com"}'
```
