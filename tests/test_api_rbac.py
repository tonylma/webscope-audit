import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.auth import create_access_token, hash_password
from app.db.base import Base
from app.db.session import get_db
from app.db.user_models import User
from app.main import app

@pytest.fixture
def api_client():
    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=test_engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

    def override_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    with TestingSession() as db:
        db.add_all([
            User(username="reader-user", display_name="Reader", password_hash=hash_password("Reader-passphrase-is-long-2026!"), role="reader", is_active=True),
            User(username="security-user", display_name="Security Analyst", password_hash=hash_password("Security-passphrase-is-long-2026!"), role="security_analyst", is_active=True),
            User(username="admin-user", display_name="Admin", password_hash=hash_password("Admin-passphrase-is-long-2026!"), role="admin", is_active=True),
        ])
        db.commit()
        users = {item.username: item for item in db.query(User).all()}

    tokens = {
        username: create_access_token(user.id, username, user.role, user.token_version)[0]
        for username, user in users.items()
    }
    try:
        with TestClient(app) as client:
            yield client, tokens
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=test_engine)
        test_engine.dispose()

def test_auth_and_role_protection(api_client):
    client, tokens = api_client
    assert client.get("/auth/me").status_code == 401
    reader_headers = {"Authorization": f"Bearer {tokens['reader-user']}"}
    analyst_headers = {"Authorization": f"Bearer {tokens['security-user']}"}
    admin_headers = {"Authorization": f"Bearer {tokens['admin-user']}"}

    assert client.get("/auth/me", headers=reader_headers).status_code == 200
    assert client.get("/auth/users", headers=reader_headers).status_code == 403
    assert client.get("/auth/users", headers=analyst_headers).status_code == 403
    assert client.get("/auth/users", headers=admin_headers).status_code == 200

def test_scan_requires_security_role_and_authorized_scope(api_client):
    client, tokens = api_client
    reader_headers = {"Authorization": f"Bearer {tokens['reader-user']}"}
    analyst_headers = {"Authorization": f"Bearer {tokens['security-user']}"}

    denied = client.post("/scan", headers=reader_headers, json={
        "url": "https://example.com", "authorized_scope": True,
    })
    assert denied.status_code == 403

    missing_consent = client.post("/scan", headers=analyst_headers, json={
        "url": "https://example.com", "authorized_scope": False,
    })
    assert missing_consent.status_code == 400

def test_fraud_evaluation_requires_fraud_role(api_client):
    client, tokens = api_client
    reader_headers = {"Authorization": f"Bearer {tokens['reader-user']}"}
    response = client.post("/fraud/evaluate", headers=reader_headers, json={})
    assert response.status_code == 403
