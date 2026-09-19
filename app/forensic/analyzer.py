import re
from urllib.parse import urlparse


DANGEROUS_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".com",
    ".msi",
    ".dll",
    ".js",
    ".vbs",
    ".vbe",
    ".wsf",
    ".ps1",
    ".jar",
    ".hta",
}


HIGH_RISK_EXTENSIONS = {
    ".zip",
    ".rar",
    ".7z",
    ".iso",
}


URGENCY_WORDS = {
    "urgent",
    "immediately",
    "act now",
    "verify now",
    "account suspended",
    "account will be closed",
    "final warning",
    "action required",
}


CREDENTIAL_WORDS = {
    "password",
    "otp",
    "one-time password",
    "verify your account",
    "login",
    "sign in",
    "credential",
    "security code",
}


def get_domain(email_address):
    if not email_address or "@" not in email_address:
        return ""

    return email_address.rsplit("@", 1)[1].lower().strip()


def analyze_authentication(forensic):
    authentication = forensic.get(
        "authentication",
        {}
    )

    findings = []
    score = 0

    spf = authentication.get(
        "spf",
        "unknown"
    )

    dkim = authentication.get(
        "dkim",
        "unknown"
    )

    dmarc = authentication.get(
        "dmarc",
        "unknown"
    )

    if spf == "fail":
        score += 15
        findings.append(
            "SPF authentication failed."
        )

    if dkim == "fail":
        score += 15
        findings.append(
            "DKIM authentication failed."
        )

    if dmarc == "fail":
        score += 20
        findings.append(
            "DMARC authentication failed."
        )

    return {
        "score": score,
        "findings": findings,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
    }


def analyze_sender(forensic):
    findings = []
    score = 0

    sender = forensic.get(
        "sender",
        {}
    )

    reply_to = forensic.get(
        "reply_to",
        {}
    )

    sender_email = sender.get(
        "email",
        ""
    )

    reply_to_email = reply_to.get(
        "email",
        ""
    )

    sender_domain = get_domain(
        sender_email
    )

    reply_domain = get_domain(
        reply_to_email
    )

    if (
        sender_domain
        and reply_domain
        and sender_domain != reply_domain
    ):
        score += 20

        findings.append(
            "Sender domain and Reply-To domain do not match."
        )

    return {
        "score": score,
        "findings": findings,
        "sender_domain": sender_domain,
        "reply_to_domain": reply_domain,
    }


def analyze_urls(forensic):
    urls = forensic.get(
        "urls",
        []
    )

    findings = []
    score = 0
    analyzed_urls = []

    sender_domain = get_domain(
        forensic.get(
            "sender",
            {}
        ).get(
            "email",
            ""
        )
    )

    for url in urls:

        try:
            parsed = urlparse(url)

            domain = (
                parsed.hostname or ""
            ).lower()

            scheme = (
                parsed.scheme or ""
            ).lower()

            url_score = 0
            url_findings = []

            if scheme != "https":
                url_score += 5

                url_findings.append(
                    "URL does not use HTTPS."
                )

            # Direct IP address instead of domain.
            if re.fullmatch(
                r"\d{1,3}(?:\.\d{1,3}){3}",
                domain,
            ):
                url_score += 20

                url_findings.append(
                    "URL uses an IP address instead of a domain name."
                )

            if (
                sender_domain
                and domain
                and domain != sender_domain
            ):
                url_score += 10

                url_findings.append(
                    "URL domain differs from the sender domain."
                )

            score += url_score

            findings.extend(url_findings)

            analyzed_urls.append({
                "url": url,
                "domain": domain,
                "score": url_score,
                "findings": url_findings,
            })

        except Exception:

            score += 10

            findings.append(
                "A URL could not be parsed safely."
            )

    return {
        "score": min(score, 40),
        "findings": findings,
        "urls": analyzed_urls,
    }


def analyze_attachments(forensic):
    attachments = forensic.get(
        "attachments",
        []
    )

    findings = []
    score = 0
    analyzed = []

    for attachment in attachments:

        filename = (
            attachment.get(
                "filename",
                ""
            )
            .lower()
            .strip()
        )

        extension = ""

        if "." in filename:
            extension = (
                "." +
                filename.rsplit(".", 1)[1]
            )

        attachment_score = 0
        attachment_findings = []

        if extension in DANGEROUS_EXTENSIONS:

            attachment_score += 35

            attachment_findings.append(
                f"Potentially dangerous attachment type: {extension}"
            )

        elif extension in HIGH_RISK_EXTENSIONS:

            attachment_score += 15

            attachment_findings.append(
                f"Archive attachment requires additional inspection: {extension}"
            )

        score += attachment_score

        findings.extend(
            attachment_findings
        )

        analyzed.append({
            "filename": filename,
            "extension": extension,
            "mime_type": attachment.get(
                "mime_type",
                ""
            ),
            "size": attachment.get(
                "size",
                0
            ),
            "score": attachment_score,
            "findings": attachment_findings,
        })

    return {
        "score": min(score, 40),
        "findings": findings,
        "attachments": analyzed,
    }


def analyze_content(forensic):
    text = (
        forensic.get(
            "body",
            {}
        ).get(
            "text",
            ""
        )
        or ""
    ).lower()

    subject = (
        forensic.get(
            "subject",
            ""
        )
        or ""
    ).lower()

    combined = text + "\n" + subject

    findings = []
    score = 0

    urgency_hits = []

    for word in URGENCY_WORDS:

        if word in combined:
            urgency_hits.append(word)

    if urgency_hits:

        score += min(
            len(urgency_hits) * 5,
            15
        )

        findings.append(
            "Urgency or pressure language detected."
        )

    credential_hits = []

    for word in CREDENTIAL_WORDS:

        if word in combined:
            credential_hits.append(word)

    if credential_hits:

        score += min(
            len(credential_hits) * 5,
            15
        )

        findings.append(
            "Credential or account-related language detected."
        )

    return {
        "score": min(score, 30),
        "findings": findings,
        "urgency_terms": urgency_hits,
        "credential_terms": credential_hits,
    }


def classify_threat(score, findings):

    finding_text = " ".join(
        findings
    ).lower()

    if (
        "potentially dangerous attachment"
        in finding_text
    ):
        threat = "MALICIOUS ATTACHMENT"

    elif (
        "credential"
        in finding_text
        and "url domain differs"
        in finding_text
    ):
        threat = "PHISHING"

    elif score >= 80:
        threat = "HIGH RISK"

    elif score >= 60:
        threat = "RISKY"

    elif score >= 30:
        threat = "SUSPICIOUS"

    else:
        threat = "SAFE"

    return threat


def analyze_email(forensic):

    authentication = (
        analyze_authentication(
            forensic
        )
    )

    sender = (
        analyze_sender(
            forensic
        )
    )

    urls = (
        analyze_urls(
            forensic
        )
    )

    attachments = (
        analyze_attachments(
            forensic
        )
    )

    content = (
        analyze_content(
            forensic
        )
    )

    total_score = (
        authentication["score"]
        + sender["score"]
        + urls["score"]
        + attachments["score"]
        + content["score"]
    )

    total_score = min(
        total_score,
        100
    )

    findings = (
        authentication["findings"]
        + sender["findings"]
        + urls["findings"]
        + attachments["findings"]
        + content["findings"]
    )

    threat = classify_threat(
        total_score,
        findings
    )

    if total_score >= 80:
        risk = "CRITICAL"
    elif total_score >= 60:
        risk = "HIGH"
    elif total_score >= 30:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "threat": threat,
        "risk_score": total_score,
        "risk_level": risk,

        "findings": findings,

        "evidence": {
            "authentication": authentication,
            "sender": sender,
            "urls": urls,
            "attachments": attachments,
            "content": content,
        },
    }