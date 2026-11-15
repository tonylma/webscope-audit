import os

# Backend imports require an explicit database URL. Tests use a disposable local SQLite DB.
os.environ.setdefault("DATABASE_URL", "sqlite:////tmp/webscope-test-suite.sqlite3")
os.environ.setdefault("WEBSCOPE_JWT_SECRET", "test-only-jwt-secret-" + "x" * 48)
os.environ.setdefault("WEBSCOPE_AUDIT_HMAC_KEY", "test-only-audit-key-" + "a" * 48)
os.environ.setdefault("WEBSCOPE_PSEUDONYMIZATION_KEY", "test-only-pseudonym-key-" + "p" * 48)
os.environ.setdefault("WEBSCOPE_DATA_ENCRYPTION_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
os.environ.setdefault("WEBSCOPE_AUDIT_LOG_PATH", "/tmp/webscope-test-audit.jsonl")
os.environ.setdefault("CORS_ORIGINS", "http://localhost:5173")
