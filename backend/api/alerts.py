from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from backend.database import get_db, AlertModel
from alerts.schema import Alert

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])

# In-memory alert store buffer for real-time fast access
in_memory_alerts: List[dict] = []

@router.get("", response_model=List[Alert])
async def get_alerts(
    limit: int = Query(50, ge=1, le=500),
    severity: Optional[str] = None,
    threat_class: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """Retrieve recent alerts with optional severity/threat filtering."""
    query = select(AlertModel).order_by(desc(AlertModel.timestamp)).limit(limit)
    if severity:
        query = query.where(AlertModel.severity == severity.upper())
    if threat_class:
        query = query.where(AlertModel.threat_class == threat_class.upper())

    result = await db.execute(query)
    db_alerts = result.scalars().all()

    if db_alerts:
        return [
            Alert(
                alert_id=a.alert_id,
                timestamp=a.timestamp,
                flow_id=a.flow_id,
                src_ip=a.src_ip,
                dst_ip=a.dst_ip,
                src_port=a.src_port,
                dst_port=a.dst_port,
                protocol=a.protocol,
                threat_class=a.threat_class,
                severity=a.severity,
                confidence=a.confidence,
                evidence=a.evidence,
                contributing_features=a.contributing_features or {},
                model_version=a.model_version
            )
            for a in db_alerts
        ]
    
    # Fallback to in-memory store if DB is empty
    filtered = in_memory_alerts
    if severity:
        filtered = [a for a in filtered if a.get("severity") == severity.upper()]
    if threat_class:
        filtered = [a for a in filtered if a.get("threat_class") == threat_class.upper()]
    
    return [Alert(**a) for a in filtered[:limit]]


@router.get("/{alert_id}", response_model=Alert)
async def get_alert_by_id(alert_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieve detailed alert by ID."""
    result = await db.execute(select(AlertModel).where(AlertModel.alert_id == alert_id))
    a = result.scalar_one_or_none()
    if a:
        return Alert(
            alert_id=a.alert_id,
            timestamp=a.timestamp,
            flow_id=a.flow_id,
            src_ip=a.src_ip,
            dst_ip=a.dst_ip,
            src_port=a.src_port,
            dst_port=a.dst_port,
            protocol=a.protocol,
            threat_class=a.threat_class,
            severity=a.severity,
            confidence=a.confidence,
            evidence=a.evidence,
            contributing_features=a.contributing_features or {},
            model_version=a.model_version
        )
    
    for a_dict in in_memory_alerts:
        if a_dict.get("alert_id") == alert_id:
            return Alert(**a_dict)

    raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
