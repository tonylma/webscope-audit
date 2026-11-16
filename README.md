# WebScope Audit & Defense

**WebScope** est une plateforme défensive qui réunit l'audit de surface web autorisé, le triage non-exécutant de fichiers suspects et un module de contrôle interne antifraude Mobile Money.

> **État du projet :** version de développement 3.1. La branche contient les fonctionnalités et tests décrits ci-dessous ; la validation complète par CI/Docker reste obligatoire avant toute utilisation en production.

## Modules

### 1. Audit de surface web autorisé

- DNS public A/AAAA et découverte limitée de sous-domaines.
- Vérification HTTP/HTTPS des en-têtes de sécurité et du certificat TLS.
- Contrôles bornés de quelques chemins sensibles par requête `HEAD`.
- Extraction de liens internes depuis le HTML, sans télécharger les ressources liées.
- Score de risque heuristique et rapport persistant.
- Confirmation explicite de l'autorisation avant chaque scan.

Le scanner API utilise des résolutions DNS contrôlées et se connecte directement aux adresses publiques résolues afin de réduire le risque SSRF et de DNS rebinding. Il limite les ports à 80/443, refuse les adresses privées/spéciales, ne suit pas les redirections inter-domaines et ne télécharge aucun fichier. Les tests de sécurité doivent toutefois être complétés avant exposition Internet.

### 2. Défense et triage de fichiers

- Détection heuristique d'indicateurs dans les URL sans ouvrir la destination.
- Reconnaissance statique de formats et empreinte SHA-256.
- Recherche de chaînes indicatrices Android/Windows sans exécution ni extraction.
- Analyse antivirus optionnelle via ClamAV `INSTREAM`, sur le réseau interne Docker.
- Conservation des résultats et journalisation des opérations, sans sauvegarde du fichier soumis.

**Un résultat sans indicateur n'est pas une preuve d'innocuité.** Pour les échantillons critiques, utiliser une sandbox dédiée, jetable, sans accès aux comptes ni réseaux de production. Ne jamais exécuter un échantillon sur un poste métier.

### 3. Fraude Mobile Money et contrôle interne

- Triage de signaux liés au SIM swap, OTP, phishing/smishing/vishing, RAT, abus d'accessibilité et intégrité applicative.
- Signaux transactionnels : vélocité, montant atypique, bénéficiaires partagés et cash-out.
- Correspondances initiales MITRE Fight Fraud Framework (F3) et MITRE ATT&CK.
- Catalogue de dix contrôles de première ligne pour les missions d'Internal Control Officer.
- Dossiers antifraude persistés, notes de revue et statuts : `open`, `under_review`, `escalated`, `resolved`, `false_positive`.

Les scores sont des aides au triage : les seuils doivent être calibrés sur des événements autorisés et documentés de l'établissement. Aucune décision de blocage, de gel ou d'accusation n'est prise automatiquement.

## Authentification et rôles

L'API utilise des jetons JWT Bearer signés HS256, une durée de vie courte et une version de jeton vérifiée en base pour permettre la révocation des sessions. Les mots de passe sont hachés avec Argon2 (via `pwdlib`). Les jetons du frontend restent en mémoire et ne sont pas stockés dans `localStorage`.

| Rôle | Accès principal |
|---|---|
| `admin` | Administration des comptes, rôle, activation, révocation, reset mot de passe, intégrité du journal |
| `security_analyst` | Audit web autorisé, analyse d'URL et triage de fichiers |
| `fraud_analyst` | Évaluation des événements, lecture et gestion des dossiers antifraude |
| `auditor` | Consultation des audits, rapports, dossiers et catalogue de contrôles |
| `reader` | Consultation limitée des historiques, scores et contrôles |

L'administrateur ne peut pas se rétrograder ou désactiver le dernier compte administrateur actif.

## Cryptographie et journalisation

- AES-256-GCM pour les entrées de dossiers antifraude, les résultats et les notes de revue. Le nonce est généré aléatoirement à chaque chiffrement ; les identifiants de dossier/champ sont authentifiés comme AAD.
- Argon2 pour les mots de passe.
- HMAC-SHA-256 et SHA-256 pour le journal chaîné, avec verrouillage de fichier inter-processus.
- HMAC distinct pour la pseudonymisation des références de dossiers.
- HTTPS obligatoire en production ; les clés doivent être injectées depuis un gestionnaire de secrets.

Le journal fichier détecte les altérations, mais ne protège pas contre un administrateur de l'hôte capable de remplacer à la fois le journal et les secrets. En production, expédier les événements vers un stockage de logs immuable/WORM séparé et gérer la rotation des clés.

## Architecture et technologies

- **API :** Python 3.11, FastAPI, Pydantic v2, SQLAlchemy, PostgreSQL.
- **Authentification :** JWT, Argon2.
- **Chiffrement :** cryptography / AES-256-GCM, HMAC-SHA-256.
- **Antivirus :** ClamAV.
- **Frontend :** React 18, TypeScript, Vite, Axios.
- **Déploiement :** Docker Compose, conteneurs non-root, backend en lecture seule, réseaux privés, secrets en variables d'environnement.

Le dépôt conserve également le package CLI historique `webscope_audit/`. Le backend API et la CLI sont deux parcours séparés ; le scanner HTTP de l'API est borné aux ports web et ne réactive pas les anciens modules de crawl/téléchargement.

## Démarrage local avec Docker

Prérequis : Docker Engine avec le plugin Compose v2, Git et OpenSSL.

```bash
git clone https://github.com/tonylma/webscope-audit.git
cd webscope-audit
cp .env.example .env
```

Générez des secrets indépendants ; remplacez les valeurs correspondantes dans le fichier `.env` :

```bash
openssl rand -hex 32   # WEBSCOPE_JWT_SECRET
openssl rand -hex 32   # WEBSCOPE_AUDIT_HMAC_KEY
openssl rand -hex 32   # WEBSCOPE_PSEUDONYMIZATION_KEY
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n'  # WEBSCOPE_DATA_ENCRYPTION_KEY
openssl rand -hex 32   # POSTGRES_PASSWORD
openssl rand -hex 16   # WEBSCOPE_BOOTSTRAP_ADMIN_PASSWORD
```

Le mot de passe d'amorçage admin doit contenir au moins 18 caractères. Utilisez une phrase secrète dédiée plutôt que la dernière valeur de 16 octets si elle est trop courte ; par exemple générez `openssl rand -hex 24`.

Remplacez aussi le mot de passe dans `DATABASE_URL` par la même valeur hexadécimale que `POSTGRES_PASSWORD`. N'ajoutez jamais le fichier `.env` à Git.

```bash
docker compose up --build -d
docker compose ps
docker compose logs -f backend clamav
```

Accès locaux :

- Frontend : http://localhost:5173
- API : http://localhost:8000
- Documentation OpenAPI : http://localhost:8000/docs (désactivée en production)
- Santé : http://localhost:8000/health

Le premier démarrage crée l'administrateur défini par `WEBSCOPE_BOOTSTRAP_ADMIN_USERNAME` et `WEBSCOPE_BOOTSTRAP_ADMIN_PASSWORD`. Après création du premier compte, supprimer ces deux variables du fichier `.env` ou les retirer du service avant les redémarrages ultérieurs.

## Tests et contrôles

```bash
python -m pip install -r backend/requirements.txt
PYTHONPATH=backend pytest -q --cov=app --cov-report=term-missing
bandit -r backend/app --severity-level high --confidence-level high
pip-audit -r backend/requirements.txt

cd frontend
npm install
npm audit --audit-level=high
npm run build
```

La CI GitHub Actions exécute les tests backend, un smoke test de démarrage/amorçage, Bandit, pip-audit, npm audit et le build TypeScript/Vite. Un état vert de CI est un prérequis avant fusion ; il ne remplace pas un pentest ni une revue de configuration de production.

## API principale

| Méthode | Route | Accès |
|---|---|---|
| POST | `/auth/login` | Public |
| GET | `/auth/me` | Utilisateur authentifié |
| GET/POST/PATCH | `/auth/users`, `/auth/users/{id}` | Admin |
| POST | `/scan` | Analyste sécurité + confirmation scope |
| GET | `/history` | Analyste, fraude, auditeur, lecteur |
| POST | `/defense/url-analysis` | Analyste sécurité, auditeur |
| POST | `/defense/file-triage` | Analyste sécurité |
| GET | `/fraud/controls`, `/fraud/framework` | Fraude, auditeur, lecteur |
| POST | `/fraud/evaluate` | Analyste fraude |
| GET/PATCH | `/fraud/cases`, `/fraud/cases/{id}` | Selon rôle et action |
| GET | `/fraud/audit/verify` | Admin |

## Limites connues à vérifier avant production

- Pas encore de migration Alembic versionnée ; `create_all` initialise les tables manquantes mais ne migre pas automatiquement une base de données existante.
- Les limites de débit en mémoire conviennent à un seul processus ; un reverse proxy/API gateway avec limiteur partagé est requis en multi-worker.
- Le journal HMAC fichier doit être exporté vers un stockage immuable externe.
- La gestion et la rotation de clés doivent être confiées à un KMS/Vault ; une rotation de `WEBSCOPE_DATA_ENCRYPTION_KEY` sans ré-chiffrement rend les anciens dossiers illisibles.
- Les règles antifraude F3 doivent être contrôlées contre la version officielle du framework, calibrées et approuvées par la gouvernance métier.
- ClamAV doit avoir téléchargé ses signatures et être disponible ; sinon le résultat renvoie explicitement un état antivirus non disponible.
- L'audit web de cette branche est une analyse de surface bornée, pas un scan réseau exhaustif.

## Licence et utilisation

Voir [LICENSE](LICENSE). Effectuer les audits uniquement sur des actifs pour lesquels une autorisation explicite a été obtenue.
