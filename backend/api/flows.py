from typing import List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from backend.database import get_db, FlowModel

router = APIRouter(prefix="/api/flows", tags=["Flows"])

# In-memory flow cache for active flows
in_memory_flows: List[dict] = []

@router.get("")
async def get_flows(limit: int = Query(50, ge=1, le=200), db: AsyncSession = Depends(get_db)):
    """Retrieve recent active flows."""
    result = await db.execute(select(FlowModel).order_by(desc(FlowModel.last_seen)).limit(limit))
    db_flows = result.scalars().all()
    if db_flows:
        return [
            {
                "flow_id": f.flow_id,
                "initiator_ip": f.initiator_ip,
                "responder_ip": f.responder_ip,
                "initiator_port": f.initiator_port,
                "responder_port": f.responder_port,
                "protocol": f.protocol,
                "total_packets": f.total_packets,
                "total_bytes": f.total_bytes,
                "duration": f.duration,
                "first_seen": f.first_seen,
                "last_seen": f.last_seen
            }
            for f in db_flows
        ]
    return in_memory_flows[:limit]
