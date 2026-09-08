import os
from datetime import datetime, timezone
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Float, Integer, JSON, DateTime, Text

DB_PATH = os.path.abspath("oracleshield.db")
DATABASE_URL = f"sqlite+aiosqlite:///{DB_PATH}"

engine = create_async_engine(DATABASE_URL, echo=False, connect_args={"check_same_thread": False})
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

class AlertModel(Base):
    __tablename__ = "alerts"

    alert_id: Mapped[str] = mapped_column(String, primary_key=True, index=True)
    timestamp: Mapped[str] = mapped_column(String, index=True)
    flow_id: Mapped[str] = mapped_column(String, index=True)
    src_ip: Mapped[str] = mapped_column(String, index=True)
    dst_ip: Mapped[str] = mapped_column(String, index=True)
    src_port: Mapped[int] = mapped_column(Integer)
    dst_port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String)
    threat_class: Mapped[str] = mapped_column(String, index=True)
    severity: Mapped[str] = mapped_column(String, index=True)
    confidence: Mapped[float] = mapped_column(Float)
    evidence: Mapped[dict] = mapped_column(JSON)
    contributing_features: Mapped[dict] = mapped_column(JSON)
    model_version: Mapped[str] = mapped_column(String)

class FlowModel(Base):
    __tablename__ = "flows"

    flow_id: Mapped[str] = mapped_column(String, primary_key=True, index=True)
    initiator_ip: Mapped[str] = mapped_column(String, index=True)
    responder_ip: Mapped[str] = mapped_column(String, index=True)
    initiator_port: Mapped[int] = mapped_column(Integer)
    responder_port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String)
    total_packets: Mapped[int] = mapped_column(Integer)
    total_bytes: Mapped[int] = mapped_column(Integer)
    duration: Mapped[float] = mapped_column(Float)
    first_seen: Mapped[float] = mapped_column(Float)
    last_seen: Mapped[float] = mapped_column(Float)

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session
