from datetime import datetime
from enum import Enum
from pydantic import BaseModel, ConfigDict, Field


class AuditAction(str, Enum):
    COLLECTION_STARTED = "collection_started"
    COLLECTION_COMPLETED = "collection_completed"
    ITEM_COLLECTED = "item_collected"
    ITEM_DEDUPLICATED = "item_deduplicated"
    REPORT_GENERATED = "report_generated"
    EMAIL_SENT = "email_sent"
    APPROVAL_RECEIVED = "approval_received"
    APPROVAL_REJECTED = "approval_rejected"
    LINKEDIN_PUBLISHED = "linkedin_published"
    LINKEDIN_SKIPPED_TEST_MODE = "linkedin_skipped_test_mode"
    ERROR = "error"


class AuditEntry(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    action: AuditAction
    report_id: str = ""
    source: str = ""
    detail: str = ""
    success: bool = True
    error_message: str = ""

    model_config = ConfigDict(use_enum_values=True)
