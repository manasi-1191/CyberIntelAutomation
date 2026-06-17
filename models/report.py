from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field

from models.vulnerability import Vulnerability
from models.threat import ThreatEvent


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EDITED_APPROVED = "edited_approved"


class DailyReport(BaseModel):
    report_id: str                 # ISO date string: "2026-06-17"
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    collection_window_hours: int = 48
    window_start: datetime
    window_end: datetime

    # Raw collected data
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    threat_events: list[ThreatEvent] = Field(default_factory=list)

    # Counts by severity / category
    critical_cve_count: int = 0
    high_cve_count: int = 0
    kev_count: int = 0
    breach_count: int = 0
    attack_count: int = 0

    # Summaries — populated by summarizer (Phase 4)
    executive_summary: str = ""    # <50 words
    detailed_summary: str = ""     # ~100 words

    # Workflow state
    approval_status: ApprovalStatus = ApprovalStatus.PENDING
    approval_received_at: Optional[datetime] = None
    approved_by: str = ""
    published_at: Optional[datetime] = None
    published_content: str = ""    # Final content used (may be edited)

    # In TEST_MODE this path holds the simulated LinkedIn post
    test_output_path: str = ""

    model_config = ConfigDict(use_enum_values=True)
