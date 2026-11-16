# Architecture technique WebScope Audit & Defense

## Runtime

```text
Navigateur React
      | Authorization: Bearer JWT
      v
FastAPI (non-root, read-only root filesystem)
      |                         |
      | SQLAlchemy              | clamd INSTREAM
      v                         v
PostgreSQL                  ClamAV
      |
      +---- audit chain (HMAC, volume persistant)
```

Docker Compose expose les ports frontend, API et PostgreSQL uniquement sur loopback. ClamAV n'expose aucun port hôte. Le backend et PostgreSQL résident sur un réseau Compose privé ; ClamAV a un accès sortant séparé pour mettre à jour ses signatures. Les échantillons ne sont pas persistés.

## Composants backend

- `app/main.py`: configuration FastAPI, contrôle fail-closed au démarrage, création des tables initiales et bootstrap du premier administrateur.
- `app/core/auth.py`: hachage Argon2 et JWT à durée courte.
- `app/api/routes/auth.py`: connexion, profil, gestion des comptes et révocation des jetons.
- `app/api/routes/reports.py` et `scans.py`: audit web, rapports et historique persistants.
- `app/services/scanner_service.py`: DNS public vérifié, connexion épinglée à une IP publique, HTTP/HTTPS, TLS, en-têtes, tests HEAD et extraction de liens internes.
- `app/services/defense_engine.py`: heuristiques URL et analyse statique des octets.
- `app/services/clamav_service.py`: protocole ClamAV INSTREAM.
- `app/services/fraud_engine.py`: règles de triage Mobile Money, correspondances F3/ATT&CK et catalogue de contrôles.
- `app/api/routes/fraud.py`: cycle de vie des dossiers antifraude et autorisation par rôle.
- `app/services/crypto_service.py`: AES-256-GCM avec nonce aléatoire et AAD.
- `app/services/audit_log.py`: journal append-only chaîné SHA-256/HMAC, validation avant append et verrouillage inter-processus.
- `app/services/startup_checks.py`: contrôle des secrets, AES key size, CORS et durée des jetons.

## Modèle d'accès

| Rôle | Capacités |
|---|---|
| admin | utilisateurs, rôles, révocation, reset mot de passe, vérification HMAC |
| security_analyst | audit web public autorisé, analyse URL, triage fichier |
| fraud_analyst | évaluation antifraude, dossiers et notes de revue |
| auditor | lecture des dossiers, contrôles et rapports |
| reader | consultation limitée des sommaires/historiques |

Les contrôles sont appliqués côté API ; masquer un bouton frontend n'est jamais considéré comme une frontière de sécurité.

## Dossiers antifraude et chiffrement

Le contenu source, l'évaluation et les notes de revue sont chiffrés en AES-256-GCM avant insertion dans PostgreSQL. L'AAD lie le ciphertext à l'identifiant du dossier et au nom de champ pour empêcher le déplacement silencieux d'un ciphertext d'un champ vers un autre. Les colonnes non sensibles (score, sévérité, statut et horodatages) restent indexables pour les files de travail. Les références métier brutes ne sont pas écrites dans le journal HMAC.

## Audit web et sécurité réseau

Le scanner :
- exige une confirmation explicite du périmètre dans l'API ;
- refuse les URL avec identifiants, les IP littérales, les hôtes locaux ou les ports non web ;
- résout A/AAAA et refuse toute destination privée/spéciale ;
- se connecte à l'IP validée plutôt que de refaire une résolution après validation ;
- limite les connexions à 80/443, les redirections à la même origine et les corps à 64 Kio ;
- utilise HEAD sur une liste courte de chemins connus ;
- n'extrait pas de fichiers distants, n'exécute pas de code et ne suit pas les redirections inter-domaines.

Cette défense ne remplace pas une segmentation réseau d'exécution et un filtrage egress au niveau infrastructure.

## Validation

Les tests se répartissent en :
- analyse heuristique URL et fichiers ;
- scanner HTTP avec sockets/DNS simulés ;
- règles antifraude et correspondances F3 ;
- chiffrement AES-GCM et rejet d'une mauvaise AAD ;
- vérification de la chaîne HMAC et détection d'altération ;
- JWT/Argon2, autorisation RBAC et routes FastAPI ;
- validation des secrets et smoke test d'initialisation.

La CI doit être verte avant fusion. Une exécution complète de Docker Compose, la disponibilité de ClamAV et la revue manuelle de la production restent à effectuer dans un environnement de déploiement.
