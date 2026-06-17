from datetime import datetime
from pydantic import BaseModel, Field


class ExtractedThreatEvent(BaseModel):
    """AI-extracted structured intelligence from a raw ThreatEvent."""
    event_id: str
    source_url: str = ""
    threat_actor: str = "unknown"
    motivation: str = "unknown"
    attack_type: str = "unknown"
    affected_sector: str = "unknown"
    affected_organizations: list[str] = Field(default_factory=list)
    impact: str = "unknown"
    enterprise_mitigations: list[str] = Field(default_factory=list)
    confidence_score: float = 0.0
    extraction_model: str = ""
    extracted_at: datetime = Field(default_factory=datetime.utcnow)
