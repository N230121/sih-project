import base64
import re
from email.utils import parseaddr


def _decode_body(data):
    if not data:
        return ""

    try:
        decoded = base64.urlsafe_b64decode(
            data + "=" * (-len(data) % 4)
        )
        return decoded.decode(
            "utf-8",
            errors="replace"
        )
    except Exception:
        return ""


def _walk_parts(part):
    """
    Recursively walk the Gmail MIME tree.
    """

    results = []

    if not part:
        return results

    results.append(part)

    for child in part.get("parts", []) or []:
        results.extend(_walk_parts(child))

    return results


def extract_message_body(payload):
    """
    Extract text/plain and text/html bodies
    from the Gmail MIME structure.
    """

    plain_parts = []
    html_parts = []

    for part in _walk_parts(payload):

        mime_type = (
            part.get("mimeType", "")
            .lower()
        )

        filename = part.get("filename", "")

        # Skip actual attachments.
        if filename:
            continue

        body = part.get("body", {})
        data = body.get("data")

        if not data:
            continue

        decoded = _decode_body(data)

        if mime_type == "text/plain":
            plain_parts.append(decoded)

        elif mime_type == "text/html":
            html_parts.append(decoded)

    return {
        "text": "\n".join(plain_parts),
        "html": "\n".join(html_parts),
    }


def extract_urls(text):
    """
    Extract HTTP/HTTPS URLs from message content.
    """

    if not text:
        return []

    pattern = r'https?://[^\s<>"\'\)\]]+'

    urls = re.findall(pattern, text)

    # Remove duplicates while preserving order.
    unique_urls = list(dict.fromkeys(urls))

    return unique_urls


def extract_attachments(payload):
    """
    Extract attachment metadata without executing
    or downloading the attachment.
    """

    attachments = []

    for part in _walk_parts(payload):

        filename = (
            part.get("filename") or ""
        ).strip()

        if not filename:
            continue

        body = part.get("body", {})

        attachments.append({
            "filename": filename,
            "mime_type": part.get("mimeType", ""),
            "size": body.get("size", 0),
            "attachment_id": body.get("attachmentId"),
        })

    return attachments


def normalize_headers(payload):
    """
    Convert Gmail header list into a case-insensitive dictionary.
    """

    headers = {}

    for header in payload.get("headers", []):

        name = header.get("name", "").strip().lower()
        value = header.get("value", "").strip()

        if name:
            headers[name] = value

    return headers


def parse_authentication_headers(headers):
    """
    Extract SPF / DKIM / DMARC information from
    Authentication-Results and related headers.
    """

    authentication_results = (
        headers.get("authentication-results", "")
    )

    received_spf = (
        headers.get("received-spf", "")
    )

    combined = (
        authentication_results +
        " " +
        received_spf
    ).lower()

    def find_result(name):
        match = re.search(
            rf"\b{name}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b",
            combined,
        )

        if match:
            return match.group(1)

        return "unknown"

    return {
        "spf": find_result("spf"),
        "dkim": find_result("dkim"),
        "dmarc": find_result("dmarc"),
        "authentication_results": authentication_results,
        "received_spf": received_spf,
    }


def parse_email_message(message):
    """
    Convert a Gmail API message into a structured
    forensic representation.
    """

    payload = message.get("payload", {})

    headers = normalize_headers(payload)

    body = extract_message_body(payload)

    combined_text = (
        body["text"] +
        "\n" +
        body["html"]
    )

    urls = extract_urls(combined_text)

    attachments = extract_attachments(payload)

    from_header = headers.get("from", "")
    reply_to = headers.get("reply-to", "")

    sender_name, sender_email = parseaddr(from_header)
    _, reply_to_email = parseaddr(reply_to)

    authentication = parse_authentication_headers(
        headers
    )

    return {
        "id": message.get("id"),
        "thread_id": message.get("threadId"),

        "headers": headers,

        "sender": {
            "name": sender_name,
            "email": sender_email,
        },

        "reply_to": {
            "email": reply_to_email,
        },

        "subject": headers.get("subject", ""),
        "date": headers.get("date", ""),

        "body": {
            "text": body["text"],
            "html": body["html"],
        },

        "urls": urls,

        "attachments": attachments,

        "authentication": authentication,

        "size_estimate": message.get(
            "sizeEstimate",
            0
        ),
    }