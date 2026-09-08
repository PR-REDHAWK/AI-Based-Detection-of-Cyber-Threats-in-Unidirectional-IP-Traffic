from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

class DetectionResult(BaseModel):
    """Standardized detection result returned by all threat detectors."""
    threat_class: str  # e.g., SYN_FLOOD, C2_BEACONING, PORT_SCAN, DGA_DOMAIN, UNKNOWN_ANOMALY
    detected: bool
    confidence: float = Field(ge=0.0, le=1.0)  # Model/rule confidence score (0.0 to 1.0)
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    evidence: Dict[str, Any]  # Key evidence metrics (e.g. periodicity_score, syn_rate)
    contributing_features: Dict[str, float] = Field(default_factory=dict)  # Normalized feature importances
    model_version: str = "v1.0"


class BaseDetector(ABC):
    """Abstract base class for all OracleShield passive detectors."""

    def __init__(self, name: str, version: str = "v1.0"):
        self.name = name
        self.version = version

    @abstractmethod
    def analyze_flow(self, flow_features: Dict[str, Any]) -> Optional[DetectionResult]:
        """Analyzes a single flow feature vector and returns a DetectionResult if suspicious."""
        pass
