from __future__ import annotations

import re
import jwt
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.auth import ALLOWED_ROLES, create_access_token, decode_access_token, hash_password, verify_password
from app.db.session import get_db
from app.db.user_models import User
from app.services.audit_log import append_event

router = APIRouter(prefix="/auth", tags=["authentication"])
bearer = HTTPBearer(auto_error=False)

class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=2, max_length=80)
    password: str = Field(min_length=1, max_length=128)

class UserCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=2, max_length=80, pattern=r"^[A-Za-z0-9_.@-]+$")
    display_name: str = Field(min_length=2, max_length=120)
    email: str | None = Field(default=None, max_length=255)
    password: str = Field(min_length=14, max_length=128)
    role: str

class UserUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: str | None = None
    is_active: bool | None = None
    display_name: str | None = Field(default=None, min_length=2, max_length=120)

class PasswordResetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    new_password: str = Field(min_length=14, max_length=128)

class PasswordChangeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=14, max_length=128)

def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
                 db: Session = Depends(get_db)) -> User:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Authentification requise.", headers={"WWW-Authenticate": "Bearer"})
    try:
        claims = decode_access_token(credentials.credentials)
        user_id = int(claims["sub"])
    except (ValueError, KeyError, jwt.InvalidTokenError, RuntimeError):
        raise HTTPException(status_code=401, detail="Jeton invalide ou expiré.", headers={"WWW-Authenticate": "Bearer"})
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active or user.token_version != claims.get("ver"):
        raise HTTPException(status_code=401, detail="Session révoquée ou compte désactivé.")
    return user

def require_roles(*roles: str):
    def dependency(user: User = Depends(current_user)) -> User:
        if user.role not in roles and user.role != "admin":
            raise HTTPException(status_code=403, detail="Rôle insuffisant pour cette opération.")
        return user
    return dependency

def _active_admin_count(db: Session) -> int:
    return db.query(User).filter(User.role == "admin", User.is_active.is_(True)).count()

@router.post("/login")
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    now = datetime.now(timezone.utc)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Identifiants invalides.")
    if user.locked_until and user.locked_until.replace(tzinfo=timezone.utc) > now:
        raise HTTPException(status_code=423, detail="Compte temporairement verrouillé.")
    if not verify_password(payload.password, user.password_hash):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= 5:
            user.locked_until = now + timedelta(minutes=15)
            user.failed_login_attempts = 0
        db.commit()
        raise HTTPException(status_code=401, detail="Identifiants invalides.")
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = now
    db.commit()
    try:
        append_event("auth.login", user.username, {"user_id": user.id, "role": user.role})
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="Journal d'audit non configuré.") from exc
    token, expires_at = create_access_token(user.id, user.username, user.role, user.token_version)
    return {
        "access_token": token, "token_type": "bearer", "expires_at": expires_at,
        "user": {"id": user.id, "username": user.username, "display_name": user.display_name, "role": user.role},
    }

@router.get("/me")
def me(user: User = Depends(current_user)):
    return {
        "id": user.id, "username": user.username, "display_name": user.display_name,
        "email": user.email, "role": user.role, "is_active": user.is_active,
    }

@router.post("/me/password")
def change_own_password(payload: PasswordChangeRequest, user: User = Depends(current_user),
                        db: Session = Depends(get_db)):
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Mot de passe actuel incorrect.")
    if payload.current_password == payload.new_password:
        raise HTTPException(status_code=422, detail="Le nouveau mot de passe doit être différent.")
    try:
        user.password_hash = hash_password(payload.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    user.password_changed_at = datetime.now(timezone.utc)
    user.token_version += 1
    db.commit()
    append_event("auth.password_changed", user.username, {"user_id": user.id, "self_service": True})
    return {"success": True, "message": "Mot de passe changé. Reconnectez-vous."}

@router.get("/users")
def list_users(_: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    users = db.query(User).order_by(User.id).all()
    return {"users": [{
        "id": item.id, "username": item.username, "display_name": item.display_name,
        "email": item.email, "role": item.role, "is_active": item.is_active,
        "created_at": item.created_at, "last_login_at": item.last_login_at,
    } for item in users]}

@router.post("/users", status_code=201)
def create_user(payload: UserCreateRequest, actor: User = Depends(require_roles("admin")),
                db: Session = Depends(get_db)):
    if payload.role not in ALLOWED_ROLES:
        raise HTTPException(status_code=422, detail="Rôle inconnu.")
    if payload.email and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", payload.email):
        raise HTTPException(status_code=422, detail="Adresse e-mail invalide.")
    try:
        digest = hash_password(payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    new_user = User(
        username=payload.username, display_name=payload.display_name, email=payload.email,
        password_hash=digest, role=payload.role, is_active=True,
    )
    try:
        db.add(new_user)
        db.flush()
        append_event("auth.user_created", actor.username, {
            "user_id": new_user.id, "role": new_user.role, "username": new_user.username,
        })
        db.commit()
        db.refresh(new_user)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Nom d'utilisateur ou e-mail déjà utilisé.") from exc
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail="Création du compte impossible.") from exc
    return {"id": new_user.id, "username": new_user.username, "role": new_user.role}

@router.patch("/users/{user_id}")
def update_user(user_id: int, payload: UserUpdateRequest,
                actor: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable.")
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=422, detail="Aucun champ à mettre à jour.")
    if "role" in changes and changes["role"] not in ALLOWED_ROLES:
        raise HTTPException(status_code=422, detail="Rôle inconnu.")
    if target.id == actor.id and (changes.get("is_active") is False or changes.get("role", "admin") != "admin"):
        raise HTTPException(status_code=400, detail="Un administrateur ne peut pas désactiver ou rétrograder son propre compte.")
    would_remove_admin = target.role == "admin" and target.is_active and (
        changes.get("role", target.role) != "admin" or changes.get("is_active", target.is_active) is False
    )
    if would_remove_admin and _active_admin_count(db) <= 1:
        raise HTTPException(status_code=409, detail="Impossible de désactiver le dernier administrateur actif.")
    for field, value in changes.items():
        setattr(target, field, value)
    if "role" in changes or changes.get("is_active") is False:
        target.token_version += 1
    try:
        append_event("auth.user_updated", actor.username, {
            "user_id": target.id, "updated_fields": sorted(changes.keys()),
            "role": target.role, "is_active": target.is_active,
        })
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail="Mise à jour du compte impossible.") from exc
    return {"id": target.id, "username": target.username, "role": target.role, "is_active": target.is_active}

@router.post("/users/{user_id}/reset-password")
def reset_user_password(user_id: int, payload: PasswordResetRequest,
                        actor: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable.")
    try:
        target.password_hash = hash_password(payload.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    target.password_changed_at = datetime.now(timezone.utc)
    target.token_version += 1
    target.failed_login_attempts = 0
    target.locked_until = None
    try:
        append_event("auth.password_reset", actor.username, {"user_id": target.id})
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail="Réinitialisation impossible.") from exc
    return {"success": True, "message": "Mot de passe réinitialisé ; toutes les sessions précédentes sont révoquées."}

@router.post("/users/{user_id}/revoke")
def revoke_user_sessions(user_id: int, actor: User = Depends(require_roles("admin")),
                         db: Session = Depends(get_db)):
    if user_id == actor.id:
        raise HTTPException(status_code=400, detail="Utilisez un autre compte administrateur pour révoquer votre propre session.")
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable.")
    target.token_version += 1
    try:
        append_event("auth.sessions_revoked", actor.username, {"user_id": target.id})
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail="Révocation des sessions impossible.") from exc
    return {"success": True}
