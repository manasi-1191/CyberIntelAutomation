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
    EMAIL_SKIPPED_NO_CREDENTIALS = "email_skipped_no_credentials"
    APPROVAL_RECEIVED = "approval_received"
    APPROVAL_REJECTED = "approval_rejected"
    APPROVAL_EDITED = "approval_edited"
    APPROVAL_TIMEOUT = "approval_timeout"
    APPROVAL_POLL_CHECKED = "approval_poll_checked"
    AI_EXTRACTION_COMPLETED = "ai_extraction_completed"
    AI_SUMMARY_GENERATED = "ai_summary_generated"
    AI_SKIPPED_NO_KEY = "ai_skipped_no_key"
    LINKEDIN_PUBLISHED = "linkedin_published"
    LINKEDIN_PUBLISH_FAILED = "linkedin_publish_failed"
    LINKEDIN_SKIPPED_TEST_MODE = "linkedin_skipped_test_mode"
    CONTENT_SAVED_TEST_MODE = "content_saved_test_mode"
    CONTENT_GATE_NOTIFICATION_SENT = "content_gate_notification_sent"
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
