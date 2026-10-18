from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, Text, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationship to analyses
    analyses = relationship("Analysis", back_populates="user", cascade="all, delete-orphan")

class Analysis(Base):
    __tablename__ = "analyses"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    email_content = Column(Text, nullable=False)
    risk_score = Column(Float, nullable=False)
    risk_level = Column(String, nullable=False)
    findings = Column(JSON, nullable=False)
    highlighted_snippets = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    brand_impersonated = Column(String, nullable=True)
    attack_type = Column(String, nullable=True)
    mitre_techniques = Column(JSON, nullable=True)

    user = relationship("User", back_populates="analyses")