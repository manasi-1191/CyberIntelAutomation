"""
Polls Gmail for an approval reply to a previously sent report email.

Protocol:
  - Sender replies "APPROVE"           → publish detailed_summary
  - Sender replies "REJECT"            → do not publish
  - Sender attaches a .txt file        → publish the attachment content instead
  - No reply found                     → return ApprovalPollResult(status="pending")

Security: only accepts replies from the configured APPROVAL_EMAIL_RECIPIENT address.
"""
import base64
import logging
from dataclasses import dataclass
from email import message_from_bytes
from email.message import Message

from emailer.gmail_auth import get_gmail_service
from config.settings import settings

logger = logging.getLogger(__name__)

_APPROVE_KEYWORDS = {"approve", "approved", "yes", "publish"}
_REJECT_KEYWORDS = {"reject", "rejected", "no", "skip", "deny"}


@dataclass
class ApprovalPollResult:
    status: str           # "approved" | "rejected" | "edited_approved" | "pending"
    approved_by: str = ""
    content: str = ""     # populated for "approved" and "edited_approved"


def check_for_reply(thread_id: str, sent_message_id: str) -> ApprovalPollResult:
    """
    Check the Gmail thread for a reply to our sent approval email.
    Returns ApprovalPollResult describing what was found.
    """
    if not thread_id:
        logger.warning("No thread_id — cannot poll for approval")
        return ApprovalPollResult(status="pending")

    service = get_gmail_service()

    try:
        thread = (
            service.users()
            .threads()
            .get(userId="me", id=thread_id, format="full")
            .execute()
        )
    except Exception as exc:
        logger.error("Failed to fetch Gmail thread %s: %s", thread_id, exc)
        return ApprovalPollResult(status="pending")

    messages = thread.get("messages", [])
    logger.debug("Thread %s has %d message(s)", thread_id, len(messages))

    for msg in messages:
        # Skip the original message we sent
        if msg.get("id") == sent_message_id:
            continue

        # Only accept replies from the designated approver
        sender = _get_header(msg, "From")
        if not _is_authorized_sender(sender):
            logger.debug("Skipping message from unauthorized sender: %s", sender)
            continue

        result = _parse_message(msg, sender)
        if result:
            return result

    return ApprovalPollResult(status="pending")


def _is_authorized_sender(from_header: str) -> bool:
    """Accept replies only from the configured approval recipient address."""
    recipient = settings.approval_email_recipient.lower().strip()
    return recipient in from_header.lower()


def _parse_message(msg: dict, sender: str) -> ApprovalPollResult | None:
    """
    Extract body and attachments from a Gmail message dict.
    Returns an ApprovalPollResult if the message contains a clear decision,
    or None if it's ambiguous (e.g. auto-reply, OOO).
    """
    mime_bytes = _decode_raw_message(msg)
    if not mime_bytes:
        return None

    mime = message_from_bytes(mime_bytes)
    body = _extract_body(mime)
    attachment_text = _extract_txt_attachment(mime)

    # Attachment takes priority over body keyword
    if attachment_text:
        logger.info("Approval reply contains .txt attachment — using edited content")
        return ApprovalPollResult(
            status="edited_approved",
            approved_by=sender,
            content=attachment_text.strip(),
        )

    # Check body for APPROVE / REJECT keyword
    body_lower = body.lower().strip()
    first_word = body_lower.split()[0] if body_lower.split() else ""

    if first_word in _APPROVE_KEYWORDS or any(k in body_lower[:100] for k in _APPROVE_KEYWORDS):
        logger.info("Approval reply: APPROVED by %s", sender)
        return ApprovalPollResult(status="approved", approved_by=sender)

    if first_word in _REJECT_KEYWORDS or any(k in body_lower[:100] for k in _REJECT_KEYWORDS):
        logger.info("Approval reply: REJECTED by %s", sender)
        return ApprovalPollResult(status="rejected", approved_by=sender)

    logger.debug("Reply from %s did not contain a clear APPROVE/REJECT keyword", sender)
    return None


def _decode_raw_message(msg: dict) -> bytes | None:
    """
    Gmail API returns message body in parts[].body.data (base64url encoded).
    We reconstruct the raw MIME bytes for parsing.
    """
    try:
        payload = msg.get("payload", {})
        # Try top-level data first (non-multipart messages)
        data = payload.get("body", {}).get("data", "")
        if data:
            return base64.urlsafe_b64decode(data + "==")

        # For multipart, reconstruct from parts
        parts_bytes = _collect_parts_bytes(payload.get("parts", []))
        if parts_bytes:
            # Build a minimal raw message with headers so email.message_from_bytes works
            headers = msg.get("payload", {}).get("headers", [])
            header_str = "\r\n".join(f"{h['name']}: {h['value']}" for h in headers)
            return (header_str + "\r\n\r\n").encode() + parts_bytes

    except Exception as exc:
        logger.debug("Could not decode message payload: %s", exc)
    return None


def _collect_parts_bytes(parts: list) -> bytes:
    result = b""
    for part in parts:
        data = part.get("body", {}).get("data", "")
        if data:
            result += base64.urlsafe_b64decode(data + "==")
        # Recurse into nested parts
        nested = part.get("parts", [])
        if nested:
            result += _collect_parts_bytes(nested)
    return result


def _extract_body(mime: Message) -> str:
    """Extract plain text body from a MIME message."""
    if mime.is_multipart():
        for part in mime.walk():
            ctype = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))
            if ctype == "text/plain" and "attachment" not in disposition:
                charset = part.get_content_charset() or "utf-8"
                try:
                    return part.get_payload(decode=True).decode(charset, errors="replace")
                except Exception:
                    pass
        return ""
    else:
        charset = mime.get_content_charset() or "utf-8"
        try:
            return mime.get_payload(decode=True).decode(charset, errors="replace")
        except Exception:
            return ""


def _extract_txt_attachment(mime: Message) -> str:
    """Return the text content of the first .txt attachment found, or empty string."""
    if not mime.is_multipart():
        return ""
    for part in mime.walk():
        disposition = str(part.get("Content-Disposition", ""))
        filename = part.get_filename() or ""
        if "attachment" in disposition and filename.lower().endswith(".txt"):
            charset = part.get_content_charset() or "utf-8"
            try:
                return part.get_payload(decode=True).decode(charset, errors="replace")
            except Exception:
                pass
    return ""


def _get_header(msg: dict, name: str) -> str:
    headers = msg.get("payload", {}).get("headers", [])
    for h in headers:
        if h.get("name", "").lower() == name.lower():
            return h.get("value", "")
    return ""
