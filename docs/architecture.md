# Documentation

## Architecture

- `backend/`: API FastAPI, moteur de scan, modèles, services, Celery
- `frontend/`: interface React/TypeScript
- `infra/`: init DB et orchestration Docker Compose
- `reports/`: rapports HTML/JSON exportés

## Endpoints API de base

- `GET /health`
- `POST /scan`
- `GET /scan/{scan_id}`
- `GET /scan/{scan_id}/report`
- `GET /history`

## Workflow MVP

1. L’utilisateur soumet une URL.
2. Le backend valide la cible.
3. Le moteur de scan réalise l’analyse DNS / HTTP / TLS / découverte.
4. Le résultat est renvoyé via l’API.
5. Le dashboard affiche le statut et le résumé.
