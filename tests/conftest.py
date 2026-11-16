import os
import sys
from pathlib import Path

# Import the FastAPI package from the backend source tree when pytest runs at repo root.
REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO_ROOT / "backend"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_ROOT))

# Tests use disposable SQLite and throwaway secrets; never use production secrets here.
os.environ.setdefault("DATABASE_URL", "sqlite:////tmp/webscope-test-suite.sqlite3")
os.environ.setdefault("WEBSCOPE_JWT_SECRET", "test-only-jwt-secret-" + "x" * 48)
os.environ.setdefault("WEBSCOPE_AUDIT_HMAC_KEY", "test-only-audit-key-" + "a" * 48)
os.environ.setdefault("WEBSCOPE_PSEUDONYMIZATION_KEY", "test-only-pseudonym-key-" + "p" * 48)
os.environ.setdefault("WEBSCOPE_DATA_ENCRYPTION_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
os.environ.setdefault("WEBSCOPE_AUDIT_LOG_PATH", "/tmp/webscope-test-audit.jsonl")
os.environ.setdefault("CORS_ORIGINS", "http://localhost:5173")
os.environ.setdefault("ACCESS_TOKEN_MINUTES", "20")
os.environ.setdefault("WEBSCOPE_BOOTSTRAP_ADMIN_USERNAME", "test-admin")
os.environ.setdefault("WEBSCOPE_BOOTSTRAP_ADMIN_PASSWORD", "Test-only-bootstrap-admin-passphrase-2026!")
os.environ.setdefault("ENVIRONMENT", "development")
