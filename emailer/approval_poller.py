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
from email.utils import parseaddr

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
    Scan the entire Gmail thread for approval replies.

    All messages from the authorised sender are examined; the *newest* valid
    decision (keyword body or .txt attachment) wins.  This ensures a corrective
    reply always supersedes an earlier invalid one.
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

    last_valid: ApprovalPollResult | None = None
    for msg in messages:
        # Skip the original message we sent
        if msg.get("id") == sent_message_id:
            continue

        # Only accept replies from the designated approver
        sender = _get_header(msg, "From")
        if not _is_authorized_sender(sender):
            logger.debug("Skipping message from unauthorized sender: %s", sender)
            continue

        result = _parse_message(service, msg, sender)
        if result:
            last_valid = result  # keep scanning — we want the newest valid decision

    if last_valid:
        return last_valid
    return ApprovalPollResult(status="pending")


def _is_authorized_sender(from_header: str) -> bool:
    """Accept replies only from the configured approval recipient address.

    Uses email.utils.parseaddr to extract the actual address from the From
    header so display names and angle-bracket formatting are handled correctly,
    and lookalike domains (evil.io appended) cannot pass a substring check.
    """
    _, addr = parseaddr(from_header)
    if not addr:
        return False
    recipient = settings.approval_email_recipient.lower().strip()
    return addr.lower().strip() == recipient


def _extract_decision_from_body(body: str) -> str | None:
    """
    Return 'approve' or 'reject' only when the first non-empty, non-quoted
    line of the reply body is exactly a decision keyword (whole-word, not
    substring).  Lines beginning with '>' are treated as quoted original-email
    text and skipped.

    Returns None if the first substantive line is not a recognised keyword,
    preventing auto-replies such as "Your request has been approved for
    processing" from triggering a publish.
    """
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(">"):   # skip quoted lines from original email
            continue
        word = stripped.lower()
        if word in _APPROVE_KEYWORDS:
            return "approve"
        if word in _REJECT_KEYWORDS:
            return "reject"
        return None   # first real line is not a decision keyword — ambiguous
    return None


def _parse_message(service, msg: dict, sender: str) -> ApprovalPollResult | None:
    """
    Inspect a Gmail message dict directly from the API payload.

    Returns an ApprovalPollResult if the message contains a clear decision,
    or None if it is ambiguous (e.g. auto-reply, OOO, invalid attachment type).

    A .txt attachment takes priority over body keywords.
    """
    payload = msg.get("payload", {})
    msg_id = msg.get("id", "")

    # Log all attachment filenames found for debugging
    _log_attachment_filenames(payload)

    # .txt attachment takes priority over body keyword
    txt_content = _fetch_txt_attachment(service, msg_id, payload)
    if txt_content is not None:
        logger.info(
            "Approval reply (msg=%s) contains .txt attachment — using edited content",
            msg_id,
        )
        return ApprovalPollResult(
            status="edited_approved",
            approved_by=sender,
            content=txt_content.strip(),
        )

    # Strict first-line keyword matching — no substring fallback
    body = _extract_body_from_payload(payload)
    decision = _extract_decision_from_body(body)
    if decision == "approve":
        logger.info("Approval reply: APPROVED by %s", sender)
        return ApprovalPollResult(status="approved", approved_by=sender)
    if decision == "reject":
        logger.info("Approval reply: REJECTED by %s", sender)
        return ApprovalPollResult(status="rejected", approved_by=sender)

    logger.debug(
        "Reply from %s (msg=%s) had no valid decision or .txt attachment",
        sender, msg_id,
    )
    return None


# ── Gmail API payload helpers ─────────────────────────────────────────────────

def _iter_parts(payload: dict):
    """Recursively yield every part in a Gmail API message payload."""
    yield payload
    for part in payload.get("parts", []):
        yield from _iter_parts(part)


def _log_attachment_filenames(payload: dict) -> None:
    """Log every non-empty filename found in the payload parts for debugging."""
    for part in _iter_parts(payload):
        filename = part.get("filename", "")
        if filename:
            logger.debug("Attachment filename in reply: %r", filename)


def _fetch_txt_attachment(service, msg_id: str, payload: dict) -> str | None:
    """
    Return the text content of the first valid .txt attachment, or None if absent.

    A "valid .txt attachment" is a part whose filename ends exactly with ".txt"
    (case-insensitive).  Files like "post.txt.rtf" do NOT qualify.

    Small attachments may be inlined in body.data; larger ones arrive via
    attachmentId and require a separate API call.

    Returns None if no valid .txt attachment exists in the message.
    """
    for part in _iter_parts(payload):
        filename = part.get("filename", "")
        if not filename:
            continue
        if not filename.lower().endswith(".txt"):
            logger.debug("Skipping non-.txt attachment: %r", filename)
            continue
        body = part.get("body", {})
        # Inline data (small attachments)
        inline_data = body.get("data", "")
        if inline_data:
            try:
                return base64.urlsafe_b64decode(inline_data + "==").decode(
                    "utf-8", errors="replace"
                )
            except Exception as exc:
                logger.warning(
                    "Failed to decode inline .txt attachment %r: %s", filename, exc
                )
                continue
        # Remote attachment — fetch via separate API call
        attachment_id = body.get("attachmentId", "")
        if not attachment_id:
            continue
        try:
            att = (
                service.users()
                .messages()
                .attachments()
                .get(userId="me", messageId=msg_id, id=attachment_id)
                .execute()
            )
            data = att.get("data", "")
            if data:
                return base64.urlsafe_b64decode(data + "==").decode(
                    "utf-8", errors="replace"
                )
            return ""
        except Exception as exc:
            logger.warning(
                "Failed to fetch .txt attachment %r (msg=%s): %s",
                filename, msg_id, exc,
            )
    return None


def _extract_body_from_payload(payload: dict) -> str:
    """
    Extract the plain-text body from a Gmail API message payload.

    Handles both non-multipart (top-level body.data) and multipart messages.
    Skips parts that carry a filename (attachments).
    """
    for part in _iter_parts(payload):
        if part.get("filename"):   # skip attachments
            continue
        if part.get("mimeType", "") != "text/plain":
            continue
        data = part.get("body", {}).get("data", "")
        if data:
            try:
                return base64.urlsafe_b64decode(data + "==").decode(
                    "utf-8", errors="replace"
                )
            except Exception:
                pass
    return ""


def _get_header(msg: dict, name: str) -> str:
    headers = msg.get("payload", {}).get("headers", [])
    for h in headers:
        if h.get("name", "").lower() == name.lower():
            return h.get("value", "")
    return ""
