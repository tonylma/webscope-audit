from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.sql import func

from app.db.base import Base

class ScanRecord(Base):
    __tablename__ = "scan_records"
    id = Column(Integer, primary_key=True, index=True)
    target_url = Column(String(500), nullable=False)
    status = Column(String(64), nullable=False, default="completed")
    risk_score = Column(Float, nullable=False, default=0.0)
    summary = Column(Text, nullable=False, default="")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

class FindingRecord(Base):
    __tablename__ = "finding_records"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey('scan_records.id', ondelete='CASCADE'), nullable=False, index=True)
    category = Column(String(64), nullable=False, default="general")
    title = Column(String(255), nullable=False)
    severity = Column(String(32), nullable=False, default="medium")
    description = Column(Text, nullable=False, default="")
    evidence = Column(Text, nullable=False, default="")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

class FraudCase(Base):
    """Fraud case data and evidence are authenticated-encrypted at application level."""
    __tablename__ = "fraud_cases"
    id = Column(Integer, primary_key=True, index=True)
    case_token = Column(String(64), nullable=False, unique=True, index=True)
    created_by_user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String(16), nullable=False, index=True)
    status = Column(String(24), nullable=False, default="open", index=True)
    encrypted_input = Column(Text, nullable=False)
    encrypted_result = Column(Text, nullable=False)
    encrypted_review_note = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    reviewed_by_user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
