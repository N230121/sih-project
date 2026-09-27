from .schemas import (
    AIInvestigationInput,
    AIEmailMetadata,
    AIAuthenticationEvidence,
    AIURL,
    AIDeterministicAnalysis,
    AIInfrastructure,
)

from .gemini import analyze_with_gemini


# ============================================================
# TEST TRACE MAIL INVESTIGATION
# ============================================================

investigation = AIInvestigationInput(

    email=AIEmailMetadata(
        sender="security@example-support.com",
        reply_to="random123@gmail.com",
        subject="URGENT: Your account will be suspended",
        date="2026-09-27",
    ),

    body="""
Your account will be suspended within 24 hours.

Please verify your account immediately by clicking
the following link:

http://example-support.com/verify

Failure to verify your account will result in
permanent account suspension.
""",

    authentication=AIAuthenticationEvidence(
        spf="fail",
        dkim="fail",
        dmarc="fail",
    ),

    urls=[
        AIURL(
            url="http://example-support.com/verify",
            hostname="example-support.com",
        )
    ],

    attachments=[],

    deterministic_analysis=AIDeterministicAnalysis(
        threat="phishing",
        risk_score=87,
        risk_level="HIGH",
        findings=[
            "Sender and Reply-To addresses do not match.",
            "SPF authentication failed.",
            "DKIM authentication failed.",
            "DMARC authentication failed.",
            "Urgent account suspension language detected.",
            "Email contains an external verification URL.",
        ],
    ),

    infrastructure=[
        AIInfrastructure(
            hostname="example-support.com",
            ip="203.0.113.10",
            country="US",
            region="Example Region",
            city="Example City",
            organization="Example Network",
            asn="AS64500",
            confidence=50,
            provider="test_data",
        )
    ],
)


# ============================================================
# RUN TEST
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 60)
    print("TraceMail Gemini Investigation Test")
    print("=" * 60)

    result = analyze_with_gemini(
        investigation
    )

    print()
    print("Classification:")
    print(result.classification)

    print()
    print("Confidence:")
    print(result.confidence)

    print()
    print("Summary:")
    print(result.summary)

    print()
    print("Key Findings:")

    for finding in result.key_findings:

        print(
            f"- {finding.finding}"
        )

        print(
            f"  {finding.explanation}"
        )

        if finding.evidence:
            print(
                f"  Evidence: {finding.evidence}"
            )

    print()
    print("Social Engineering:")

    for technique in result.social_engineering:

        print(
            f"- {technique.technique} "
            f"({technique.confidence})"
        )

    print()
    print("Recommended Action:")
    print(result.recommended_action)

    print()
    print("Uncertainties:")

    for uncertainty in result.uncertainties:
        print(
            f"- {uncertainty}"
        )

    print()
    print("=" * 60)
    print("Gemini investigation test completed.")
    print("=" * 60)