import json
from typing import Optional

from google import genai

from ..config import (
    GEMINI_API_KEY,
    GEMINI_MODEL,
)

from .schemas import (
    AIInvestigationInput,
    AIInvestigationOutput,
)


# ============================================================
# GEMINI CLIENT
# ============================================================

_client: Optional[genai.Client] = None


def get_gemini_client():
    """
    Create the Gemini client lazily.

    Gemini is initialized only when an investigation
    actually requests AI analysis.
    """

    global _client

    if _client is None:

        if not GEMINI_API_KEY:
            raise RuntimeError(
                "GEMINI_API_KEY is not configured."
            )

        _client = genai.Client(
            api_key=GEMINI_API_KEY
        )

    return _client

def get_gemini_status() -> dict:
    """
    Return the current Gemini configuration status.

    This does not make an API request.
    """

    return {
        "configured": bool(GEMINI_API_KEY),
        "model": GEMINI_MODEL,
        "provider": "google_gemini",
    }

# ============================================================
# GEMINI SYSTEM INSTRUCTION
# ============================================================

GEMINI_SYSTEM_INSTRUCTION = """
You are the AI forensic analyst inside TraceMail AI.

Your task is to analyze email security investigations
using ONLY the evidence supplied by TraceMail.

TraceMail's deterministic forensic engine has already
observed and extracted the following:

- sender information
- Reply-To information
- authentication results
- URLs
- attachments
- deterministic security findings
- infrastructure intelligence

Your job is to interpret those observations.

IMPORTANT RULES:

1. Do not invent facts.

2. Do not claim that an IP address belongs to an attacker.

3. Do not infer a person's physical location from an IP address.

4. Do not invent WHOIS information, DNS information,
   authentication results, URLs, domains, organizations,
   countries, or infrastructure relationships.

5. Every important finding must be supported by evidence
   present in the supplied investigation.

6. Clearly distinguish observed evidence from interpretation.

7. If evidence is insufficient, express uncertainty.

8. Analyze the specific email supplied.
   Do not give generic textbook explanations.

9. Identify social-engineering techniques only when
   supported by the supplied email evidence.

10. Recommended actions must be defensive and appropriate
    for an email security analyst.

11. The classification describes the email itself,
    not the identity or intent of a real-world person.

12. Use deterministic analysis as evidence, but interpret
    the evidence independently.
13. Evidence IDs are controlled by TraceMail.
    Never create, modify, or invent evidence IDs.

14. Correlations must reference only evidence IDs
    present in the supplied evidence_fusion package.

15. A correlation is an interpretation of supplied
    evidence and is not itself an observed fact.

16. Never convert uncertainty into certainty.

17. If a field is missing, do not fill it using
    external knowledge or assumptions.

18. Never claim that an infrastructure resource
    belongs to a specific person or attacker unless
    that fact is explicitly present in the supplied
    evidence.

19. Never claim that a country or city associated
    with an IP address represents the physical
    location of the sender.

20. Never use the BERT classification as ground truth.

21. Never use the deterministic risk score as proof
    of malicious intent.

22. If multiple signals disagree, preserve the
    disagreement in the output.

23. Evidence must come before interpretation:
    first identify what TraceMail observed,
    then explain what those observations may indicate.

Return ONLY the requested structured JSON output.
"""


# ============================================================
# PREPARE TRACE MAIL EVIDENCE
# ============================================================

def _prepare_input(
    investigation: AIInvestigationInput,
) -> str:
    """
    Convert the TraceMail investigation object into a
    controlled JSON evidence package for Gemini.
    """

    evidence = investigation.model_dump(
        exclude_none=True
    )

    # Prevent unnecessarily large prompts.
    body = evidence.get("body", "")

    if len(body) > 12000:

        evidence["body"] = (
            body[:12000]
            + "\n\n[EMAIL BODY TRUNCATED BY TRACEMAIL]"
        )

    return json.dumps(
        evidence,
        indent=2,
        ensure_ascii=False,
        default=str,
    )

def _validate_evidence_correlations(
    result: AIInvestigationOutput,
    investigation: AIInvestigationInput,
) -> None:
    """
    Validate that Gemini correlations reference only
    evidence IDs actually supplied by TraceMail.
    """

    evidence_fusion = (
        investigation.evidence_fusion
    )

    if not evidence_fusion:
        return

    valid_ids = {
        item.id
        for item in evidence_fusion.observed_evidence
    }

    for correlation in result.correlations:

        for evidence_id in correlation.evidence:

            if evidence_id not in valid_ids:

                raise RuntimeError(
                    "Gemini returned an invalid evidence "
                    f"reference: {evidence_id}"
                )
def _validate_key_findings(
    result: AIInvestigationOutput,
    investigation: AIInvestigationInput,
) -> None:
    """
    Validate evidence references contained in key findings.
    """

    evidence_fusion = (
        investigation.evidence_fusion
    )

    if not evidence_fusion:
        return

    valid_ids = {
        item.id
        for item in evidence_fusion.observed_evidence
    }

    for finding in result.key_findings:

        if not finding.evidence:
            continue

        references = [
            part.strip()
            for part in finding.evidence.split(",")
        ]

        for reference in references:

            if not reference:
                continue

            if reference not in valid_ids:

                raise RuntimeError(
                    "Gemini returned an invalid evidence "
                    f"reference in key finding: {reference}"
                )

# ============================================================
# ANALYZE INVESTIGATION WITH GEMINI
# ============================================================

def analyze_with_gemini(
    investigation: AIInvestigationInput,
) -> AIInvestigationOutput:
    
    """
    Send one TraceMail investigation to Gemini and return
    a validated AIInvestigationOutput object.
    """

    client = get_gemini_client()

    evidence_package = _prepare_input(
        investigation
    )

    prompt = f"""
Analyze the following TraceMail email investigation.

The JSON contains evidence already observed or extracted
by TraceMail.

Determine:

- whether the email is BENIGN, PHISHING, or UNCERTAIN
- confidence
- an evidence-grounded summary
- the important evidence supporting the classification
- meaningful correlations between evidence items
- important security findings
- supported social-engineering techniques
- a defensive recommended action
- meaningful uncertainty

KEY FINDINGS
============

Each key finding must explain:

1. What was observed.
2. Why it matters for the investigation.
3. Which supplied evidence supports it.

The "evidence" field of a key finding should
contain a concise reference to the relevant
TraceMail evidence.

Do not introduce technical facts that are absent
from the investigation.
SOCIAL ENGINEERING
==================

Identify a social-engineering technique only when
the supplied email content supports it.

Examples may include:

- urgency
- credential harvesting
- impersonation
- account suspension pressure
- financial pressure

Do not assign a technique merely because the
email was classified as phishing.

If there is insufficient evidence, return an
empty list.


Do not invent missing information.

TRACE MAIL INVESTIGATION EVIDENCE
=================================
You are the AI reasoning layer of TraceMail AI, a defensive email-security investigation system.

Your job is to interpret and correlate evidence collected by deterministic forensic analysis, infrastructure intelligence, and optional machine-learning models.

SECURITY RULES:

1. Never invent an IP address, hostname, country, city, ASN, organization, authentication result, URL, attachment, sender, or other technical fact.

2. Treat observed evidence supplied by the forensic parser and infrastructure provider as the factual evidence available to you.

3. Clearly distinguish:
   - observed evidence
   - deterministic findings
   - machine-learning signals
   - your own interpretation

4. A BERT prediction is a supporting ML signal, not ground truth.

5. A deterministic risk score is a rule-based signal, not proof of malicious intent.

6. If signals disagree, explicitly describe the disagreement.

7. If important evidence is missing, report it as an uncertainty.

8. Infrastructure geolocation describes the observed network resource. It does NOT prove the physical location of the sender, attacker, or organization.

9. Do not infer a person's identity, physical location, or malicious ownership from an IP address or hosting provider alone.

10. Do not turn infrastructure metadata into unsupported claims.

11. Use the supplied evidence to explain why the classification is supported or uncertain.

12. Recommended actions should be defensive and appropriate for an email-security analyst.

13. Return ONLY the requested structured output.

The final answer must contain:

- classification
- confidence
- summary
- evidence
- correlations
- key_findings
- social_engineering
- recommended_action
- uncertainties

EVIDENCE FUSION RULES:

1. The "evidence_fusion" object is the primary
   structured evidence package for reasoning.

2. Use "observed_evidence" to identify facts
   directly observed or extracted by TraceMail.

3. Use "deterministic_findings" as rule-based
   security observations.

4. Use "infrastructure_evidence" only to describe
   observed network infrastructure.

5. Use "bert_signal" only as a supporting
   machine-learning signal.

6. Do not treat BERT confidence as proof.

7. When deterministic analysis and BERT agree,
   describe the agreement as supporting evidence.

8. When deterministic analysis and BERT disagree,
   explicitly report the disagreement.

9. Do not resolve disagreement by inventing facts.

10. Correlations must connect evidence items that
    are actually present in the supplied package.

11. Every important conclusion must be traceable
    to supplied evidence.

12. If evidence does not support a conclusion,
    place the limitation in "uncertainties".

13. Infrastructure location describes the observed
    network resource and must never be presented
    as the physical location of a sender or attacker.
CORRELATION RULES
=================

1. Correlations must reference actual evidence IDs.

2. Do not create evidence IDs that are not present.

3. A correlation must connect two or more supplied
   evidence items.

4. Explain what relationship exists between the
   referenced evidence.

5. Do not treat correlation as proof of malicious intent.

6. If evidence points in different directions,
   explicitly describe the disagreement.

7. If BERT disagrees with deterministic analysis,
   report the disagreement instead of inventing
   an explanation for it.

8. Infrastructure information may support an
   investigation but does not establish the identity
   or physical location of a sender.

9. Do not infer physical location from infrastructure.

10. Do not infer ownership of an IP address from
    infrastructure metadata alone.

11. If evidence is insufficient, use uncertainties.

12. Every major conclusion must be traceable to
    supplied evidence IDs.
CORRELATION FORMAT
==================

For each meaningful correlation, return:

{
    "evidence": ["E1", "E3"],
    "conclusion": "Explain the relationship between E1 and E3.",
    "confidence": 0.0
}

Use only evidence IDs that exist in
evidence_fusion.observed_evidence.

Do not use arbitrary evidence descriptions
inside the "evidence" array.

FINAL VALIDATION BEFORE RESPONDING
==================================

Before returning the structured result, verify:

1. Every technical fact exists in the supplied evidence.

2. Every correlation references real evidence IDs.

3. Every key finding is supported by evidence.

4. BERT is described only as an ML signal.

5. Deterministic analysis is described only as
   rule-based evidence.

6. Infrastructure is not presented as proof of
   sender identity or physical location.

7. Missing information is represented as uncertainty.

8. No unsupported URL, IP, hostname, organization,
   country, city, ASN, or authentication result
   has been introduced.

9. The classification concerns the email, not a
   real-world person's identity or intent.

{evidence_package}
"""

    # --------------------------------------------------------
    # Call Gemini Interactions API
    # --------------------------------------------------------

    interaction = client.interactions.create(

        model=GEMINI_MODEL,

        input=prompt,

        system_instruction=(
            GEMINI_SYSTEM_INSTRUCTION
        ),

        response_format={
            "type": "text",
            "mime_type": "application/json",
            "schema": (
                AIInvestigationOutput
                .model_json_schema()
            ),
        },
    )

    # --------------------------------------------------------
    # Read Gemini output
    # --------------------------------------------------------

    output_text = (
        interaction.output_text
        if interaction.output_text
        else ""
    ).strip()

    if not output_text:

        raise RuntimeError(
            "Gemini returned an empty structured response."
        )

    # --------------------------------------------------------
    # Validate structured JSON
    # --------------------------------------------------------

    try:

        result = (
            AIInvestigationOutput
            .model_validate_json(
                output_text
            )
        )

    except Exception as exc:

        raise RuntimeError(
            "Gemini returned invalid structured output: "
            f"{exc}"
        ) from exc
    
    _validate_evidence_correlations(
        result,
        investigation,
    )

    _validate_key_findings(
        result,
        investigation,
    )


    return result