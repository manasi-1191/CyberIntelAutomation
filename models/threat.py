from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class ThreatCategory(str, Enum):
    CYBER_ATTACK = "cyber_attack"
    DATA_BREACH = "data_breach"
    RANSOMWARE = "ransomware"
    APT = "apt"
    PHISHING = "phishing"
    SUPPLY_CHAIN = "supply_chain"
    VULNERABILITY_EXPLOIT = "vulnerability_exploit"
    OTHER = "other"


class ThreatActor(BaseModel):
    name: str
    aliases: list[str] = Field(default_factory=list)
    nation_state: Optional[str] = None
    motivation: str = ""           # e.g. "Financial", "Espionage", "Disruption"
    first_seen: Optional[datetime] = None


class ThreatEvent(BaseModel):
    # Identity
    event_id: str                  # stable hash of title + source + date
    source: str
    source_url: str = ""
    title: str = ""

    # Classification
    category: ThreatCategory = ThreatCategory.OTHER
    tags: list[str] = Field(default_factory=list)

    # Content
    description: str = ""
    affected_sectors: list[str] = Field(default_factory=list)
    affected_organizations: list[str] = Field(default_factory=list)
    affected_countries: list[str] = Field(default_factory=list)
    threat_actors: list[ThreatActor] = Field(default_factory=list)
    cve_references: list[str] = Field(default_factory=list)

    # Consequences
    estimated_impact: str = ""
    records_exposed: Optional[int] = None

    # Mitigation
    mitigation_recommendations: list[str] = Field(default_factory=list)

    # Timestamps
    published_at: Optional[datetime] = None
    collected_at: datetime = Field(default_factory=datetime.utcnow)

    # Dedup key
    dedup_hash: str = ""

    model_config = ConfigDict(use_enum_values=True)
