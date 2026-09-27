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
- why the email received that classification
- important security findings
- supported social-engineering techniques
- a defensive recommended action
- meaningful uncertainty

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
- key_findings
- correlations
- social_engineering
- recommended_action
- uncertainties


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
            "Gemini returned an empty response."
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

    return result