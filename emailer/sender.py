"""
Sends the approval email via Gmail API.
Returns (thread_id, message_id) so they can be stored on the report for later polling.
TEST_MODE: still sends — just to whatever APPROVAL_EMAIL_RECIPIENT is set to in .env.
"""
import base64
import logging
from datetime import datetime
from email.message import Message
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

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


def send_failure_notification(report: DailyReport, reason: str) -> None:
    """
    Send a plain-text notification when the content gate blocks the approval email.
    Raises on failure — caller is responsible for catching and logging.
    """
    body = (
        f"The daily CyberIntel briefing for {report.report_id} could not be sent "
        f"because the following content field was not ready:\n\n"
        f"  {reason}\n\n"
        f"Likely cause: AI provider quota exceeded or API key error.\n\n"
        f"Nothing was published to LinkedIn.\n\n"
        f"To fix:\n"
        f"  1. Check your AI provider quota / API key in .env\n"
        f"  2. Re-run:  python main.py summarize --report-id {report.report_id}\n"
        f"  3. Re-send: python main.py send-email --report-id {report.report_id}\n"
    )
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = f"[CyberIntel] Briefing generation failed — {report.report_id}"
    msg["From"] = settings.approval_email_sender
    msg["To"] = settings.approval_email_recipient

    service = get_gmail_service()
    raw = _encode_message(msg)
    service.users().messages().send(userId="me", body={"raw": raw}).execute()

    logger.info(
        "Content gate failure notification sent to %s for report %s — %s",
        settings.approval_email_recipient, report.report_id, reason,
    )


def _encode_message(msg: Message) -> str:
    """Encode a MIME message to the URL-safe base64 format Gmail API expects."""
    raw_bytes = msg.as_bytes()
    return base64.urlsafe_b64encode(raw_bytes).decode("utf-8")
