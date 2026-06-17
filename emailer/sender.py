"""
Sends the approval email via Gmail API.
Returns (thread_id, message_id) so they can be stored on the report for later polling.
TEST_MODE: still sends — just to whatever APPROVAL_EMAIL_RECIPIENT is set to in .env.
"""
import base64
import logging
from datetime import datetime
from email.mime.multipart import MIMEMultipart

from config.settings import settings
from emailer.gmail_auth import get_gmail_service
from models.report import DailyReport
from emailer.composer import build_approval_email

logger = logging.getLogger(__name__)


def send_approval_email(report: DailyReport) -> tuple[str, str]:
    """
    Build and send the approval email for the given report.
    Returns (thread_id, message_id).
    Raises on failure — caller should catch and audit-log.
    """
    if settings.test_mode:
        logger.info(
            "TEST_MODE=true — sending email to test recipient: %s",
            settings.approval_email_recipient,
        )

    msg = build_approval_email(report)
    msg["From"] = settings.approval_email_sender
    msg["To"] = settings.approval_email_recipient

    raw = _encode_message(msg)
    service = get_gmail_service()

    result = (
        service.users()
        .messages()
        .send(userId="me", body={"raw": raw})
        .execute()
    )

    thread_id: str = result.get("threadId", "")
    message_id: str = result.get("id", "")

    logger.info(
        "Approval email sent | to=%s | thread_id=%s | message_id=%s",
        settings.approval_email_recipient,
        thread_id,
        message_id,
    )
    return thread_id, message_id


def _encode_message(msg: MIMEMultipart) -> str:
    """Encode a MIME message to the URL-safe base64 format Gmail API expects."""
    raw_bytes = msg.as_bytes()
    return base64.urlsafe_b64encode(raw_bytes).decode("utf-8")
