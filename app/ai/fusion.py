"""
Evidence Fusion Layer

This module combines:
    1. Parsed forensic evidence
    2. Deterministic security findings
    3. Infrastructure intelligence
    4. Optional BERT classification

into one structured evidence package for the AI reasoning layer.

Important security principle:

Gemini is an interpretation layer.
It must not invent missing technical evidence.
"""


from typing import Any, Dict, List, Optional

from .schemas import (
    AIBERTSignal,
    AIDeterministicAnalysis,
    AIEvidenceFusion,
    AIEvidenceItem,
    AIInfrastructure,
)


def _add_evidence(
    evidence: List[AIEvidenceItem],
    category: str,
    observation: str,
    source: str,
    significance: Optional[str] = None,
) -> None:
    """
    Add one evidence item while avoiding empty observations.
    """

    if not observation:
        return

    evidence.append(
        AIEvidenceItem(
            id=f"E{len(evidence) + 1}",
            category=category,
            observation=observation,
            source=source,
            significance=significance,
        )
    )


def build_evidence_package(
    parsed_email: Dict[str, Any],
    deterministic_analysis: Dict[str, Any],
    infrastructure: Optional[List[Dict[str, Any]]] = None,
    bert_signal: Optional[Dict[str, Any]] = None,
) -> AIEvidenceFusion:
    """
    Build the unified evidence package.

    This function does NOT decide whether an email is malicious.

    It only organizes evidence already observed or produced by
    other security components.
    """

    evidence: List[AIEvidenceItem] = []

    infrastructure = infrastructure or []

    # ========================================================
    # 1. EMAIL METADATA
    # ========================================================

    sender = parsed_email.get("sender")
    reply_to = parsed_email.get("reply_to")
    subject = parsed_email.get("subject")
    date = parsed_email.get("date")

    if sender:
        _add_evidence(
            evidence,
            category="sender",
            observation=f"Sender: {sender}",
            source="forensic_parser",
        )

    if reply_to:
        _add_evidence(
            evidence,
            category="reply_to",
            observation=f"Reply-To: {reply_to}",
            source="forensic_parser",
        )

    if subject:
        _add_evidence(
            evidence,
            category="email_metadata",
            observation=f"Subject: {subject}",
            source="forensic_parser",
        )

    if date:
        _add_evidence(
            evidence,
            category="email_metadata",
            observation=f"Date: {date}",
            source="forensic_parser",
        )

    # ========================================================
    # 2. AUTHENTICATION EVIDENCE
    # ========================================================

    authentication = parsed_email.get("authentication") or {}

    for mechanism in ("spf", "dkim", "dmarc"):
        value = authentication.get(mechanism)

        if value:
            _add_evidence(
                evidence,
                category="authentication",
                observation=f"{mechanism.upper()}: {value}",
                source="forensic_parser",
                significance=(
                    "Email authentication result observed in "
                    "message headers."
                ),
            )

    # ========================================================
    # 3. SENDER / REPLY-TO RELATIONSHIP
    # ========================================================

    if sender and reply_to:
        _add_evidence(
            evidence,
            category="identity_relationship",
            observation=(
                f"Sender is {sender} while Reply-To is {reply_to}"
            ),
            source="forensic_parser",
            significance=(
                "The sender and Reply-To identities should be "
                "considered together during investigation."
            ),
        )

    # ========================================================
    # 4. URL EVIDENCE
    # ========================================================

    urls = parsed_email.get("urls") or []

    for url_item in urls:
        if isinstance(url_item, dict):
            url = url_item.get("url") or url_item.get("value")
            hostname = url_item.get("hostname")
        else:
            url = str(url_item)
            hostname = None

        if not url:
            continue

        observation = f"URL: {url}"

        if hostname:
            observation += f" | Hostname: {hostname}"

        _add_evidence(
            evidence,
            category="url",
            observation=observation,
            source="forensic_parser",
        )

    # ========================================================
    # 5. ATTACHMENT EVIDENCE
    # ========================================================

    attachments = parsed_email.get("attachments") or []

    for attachment in attachments:
        if not isinstance(attachment, dict):
            continue

        filename = attachment.get("filename")
        content_type = attachment.get("content_type")
        size = attachment.get("size")

        details = []

        if filename:
            details.append(f"filename={filename}")

        if content_type:
            details.append(f"content_type={content_type}")

        if size is not None:
            details.append(f"size={size}")

        if details:
            _add_evidence(
                evidence,
                category="attachment",
                observation="Attachment: " + ", ".join(details),
                source="forensic_parser",
            )

    # ========================================================
    # 6. BODY EVIDENCE
    # ========================================================

    body = parsed_email.get("body") or ""

    if isinstance(body, dict):
        text_body = body.get("text") or ""
        html_body = body.get("html") or ""

        if text_body:
            _add_evidence(
                evidence,
                category="content",
                observation=(
                    "Plain-text email body was successfully extracted."
                ),
                source="forensic_parser",
            )

        if html_body:
            _add_evidence(
                evidence,
                category="content",
                observation=(
                    "HTML email body was successfully extracted."
                ),
                source="forensic_parser",
            )

    elif body:
        _add_evidence(
            evidence,
            category="content",
            observation="Email body was successfully extracted.",
            source="forensic_parser",
        )

    # ========================================================
    # 7. DETERMINISTIC FINDINGS
    # ========================================================

    deterministic_findings = (
        deterministic_analysis.get("findings") or []
    )

    for finding in deterministic_findings:
        if finding:
            _add_evidence(
                evidence,
                category="deterministic_finding",
                observation=str(finding),
                source="deterministic_analyzer",
            )

    # Threat / risk information is also retained.
    threat = deterministic_analysis.get("threat")
    risk_score = deterministic_analysis.get("risk_score")
    risk_level = deterministic_analysis.get("risk_level")

    if threat:
        _add_evidence(
            evidence,
            category="deterministic_analysis",
            observation=f"Threat classification: {threat}",
            source="deterministic_analyzer",
        )

    if risk_score is not None:
        _add_evidence(
            evidence,
            category="deterministic_analysis",
            observation=f"Risk score: {risk_score}",
            source="deterministic_analyzer",
        )

    if risk_level:
        _add_evidence(
            evidence,
            category="deterministic_analysis",
            observation=f"Risk level: {risk_level}",
            source="deterministic_analyzer",
        )

    # ========================================================
    # 8. INFRASTRUCTURE EVIDENCE
    # ========================================================

    infrastructure_models: List[AIInfrastructure] = []

    for item in infrastructure:
        if not isinstance(item, dict):
            continue

        infrastructure_models.append(
            AIInfrastructure(
                hostname=item.get("hostname"),
                ip=item.get("ip"),
                country=item.get("country"),
                region=item.get("region"),
                city=item.get("city"),
                isp=item.get("isp"),
                organization=item.get("organization"),
                asn=item.get("asn"),
                latitude=item.get("latitude"),
                longitude=item.get("longitude"),
                vpn=item.get("vpn"),
                proxy=item.get("proxy"),
                tor=item.get("tor"),
                confidence=item.get("confidence"),
                provider=item.get("provider"),
            )
        )

        infrastructure_description = []

        if item.get("hostname"):
            infrastructure_description.append(
                f"hostname={item['hostname']}"
            )

        if item.get("ip"):
            infrastructure_description.append(
                f"ip={item['ip']}"
            )

        if item.get("country"):
            infrastructure_description.append(
                f"country={item['country']}"
            )

        if item.get("region"):
            infrastructure_description.append(
                f"region={item['region']}"
            )

        if item.get("city"):
            infrastructure_description.append(
                f"city={item['city']}"
            )

        if item.get("asn"):
            infrastructure_description.append(
                f"asn={item['asn']}"
            )

        if item.get("organization"):
            infrastructure_description.append(
                f"organization={item['organization']}"
            )

        if item.get("provider"):
            infrastructure_description.append(
                f"provider={item['provider']}"
            )

        if item.get("confidence") is not None:
            infrastructure_description.append(
                f"confidence={item['confidence']}"
            )

        if infrastructure_description:
            _add_evidence(
                evidence,
                category="infrastructure",
                observation=(
                    " | ".join(infrastructure_description)
                ),
                source="infrastructure_intelligence",
                significance=(
                    "Infrastructure metadata describes the observed "
                    "network resource associated with an extracted URL. "
                    "It does not establish the physical location or "
                    "identity of the sender."
                ),
            )

    # ========================================================
    # 9. BERT SIGNAL
    # ========================================================

    bert_model = None

    if bert_signal:
        bert_model = AIBERTSignal(
            classification=bert_signal.get("classification"),
            confidence=bert_signal.get("confidence"),
            model=bert_signal.get("model"),
        )

        if (
            bert_model.classification
            or bert_model.confidence is not None
        ):
            _add_evidence(
                evidence,
                category="ml_signal",
                observation=(
                    f"BERT classification="
                    f"{bert_model.classification}, "
                    f"confidence={bert_model.confidence}"
                ),
                source="bert_classifier",
                significance=(
                    "Machine-learning signal used as supporting "
                    "evidence, not as ground truth."
                ),
            )

    return AIEvidenceFusion(
        observed_evidence=evidence,
        deterministic_findings=[
            str(item)
            for item in deterministic_findings
            if item
        ],
        infrastructure_evidence=infrastructure_models,
        bert_signal=bert_model,
    )