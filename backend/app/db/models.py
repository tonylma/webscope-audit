from sqlalchemy import Column, DateTime, Float, Integer, String, Text
from sqlalchemy.sql import func

from app.db.base import Base


class ScanRecord(Base):
    __tablename__ = 'scan_records'

    id = Column(Integer, primary_key=True, index=True)
    target_url = Column(String(500), nullable=False)
    status = Column(String(64), default='pending')
    risk_score = Column(Float, default=0.0)
    summary = Column(Text, default='')
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class DomainRecord(Base):
    __tablename__ = 'domain_records'

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    ip = Column(String(64), nullable=True)
    record_type = Column(String(32), default='A')
    status = Column(String(32), default='active')


class UrlDiscoveryRecord(Base):
    __tablename__ = 'url_discovery_records'

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, nullable=False, index=True)
    url = Column(String(500), nullable=False)
    source = Column(String(64), default='crawl')
    status_code = Column(Integer, default=0)
    depth = Column(Integer, default=0)


class FindingRecord(Base):
    __tablename__ = 'finding_records'

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, nullable=False, index=True)
    category = Column(String(64), default='general')
    title = Column(String(255), nullable=False)
    severity = Column(String(32), default='medium')
    description = Column(Text, default='')
    evidence = Column(Text, default='')


class PublicFileRecord(Base):
    __tablename__ = 'public_file_records'

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, nullable=False, index=True)
    url = Column(String(500), nullable=False)
    file_type = Column(String(64), default='unknown')
    size_bytes = Column(Integer, default=0)
    sha256 = Column(String(128), default='')
    risk_level = Column(String(32), default='low')
