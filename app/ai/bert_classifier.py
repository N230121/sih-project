from pathlib import Path
from typing import Dict

import torch
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
)


# ============================================================
# FINE-TUNED TRACEMAIL BERT MODEL
# ============================================================

MODEL_DIR = (
    Path(__file__).resolve().parent
    / "saved_model_finetuned"
)

MAX_LENGTH = 128


class BERTClassifier:
    """
    TraceMail fine-tuned DistilBERT classifier.

    The model was fine-tuned on the phishing/benign
    email dataset and is used only as a supporting
    machine-learning signal.

    It does NOT make the final security decision.
    """

    def __init__(self):

        if not MODEL_DIR.exists():
            raise FileNotFoundError(
                f"Fine-tuned BERT model not found at: {MODEL_DIR}"
            )

        # ----------------------------------------------------
        # Load tokenizer
        # ----------------------------------------------------

        self.tokenizer = AutoTokenizer.from_pretrained(
            str(MODEL_DIR)
        )

        # ----------------------------------------------------
        # Load fine-tuned model
        # ----------------------------------------------------

        self.model = (
            AutoModelForSequenceClassification
            .from_pretrained(
                str(MODEL_DIR)
            )
        )

        # ----------------------------------------------------
        # Production inference mode
        # ----------------------------------------------------

        self.model.eval()

        # ----------------------------------------------------
        # Label mapping used during training
        # ----------------------------------------------------

        self.labels = {
            0: "BENIGN",
            1: "PHISHING",
        }

    def predict(
        self,
        text: str,
    ) -> Dict:
        """
        Predict whether an email is BENIGN or PHISHING.

        Returns:
            classification
            confidence
            model
        """

        # ----------------------------------------------------
        # Empty input
        # ----------------------------------------------------

        if not text or not text.strip():

            return {
                "classification": "UNKNOWN",
                "confidence": 0.0,
                "model": "TraceMail-FineTuned-DistilBERT",
            }

        # ----------------------------------------------------
        # Tokenize
        # ----------------------------------------------------

        inputs = self.tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=MAX_LENGTH,
            padding=True,
        )

        # ----------------------------------------------------
        # Inference
        # ----------------------------------------------------

        with torch.no_grad():

            outputs = self.model(
                **inputs
            )

        # ----------------------------------------------------
        # Convert logits → probabilities
        # ----------------------------------------------------

        probabilities = torch.softmax(
            outputs.logits,
            dim=-1,
        )[0]

        # ----------------------------------------------------
        # Find predicted class
        # ----------------------------------------------------

        predicted_id = int(
            torch.argmax(
                probabilities
            ).item()
        )

        confidence = float(
            probabilities[
                predicted_id
            ].item()
        )

        classification = self.labels.get(
            predicted_id,
            "UNKNOWN",
        )

        return {
            "classification": classification,
            "confidence": round(
                confidence,
                4,
            ),
            "model": (
                "TraceMail-FineTuned-DistilBERT"
            ),
        }


# ============================================================
# SIMPLE LOCAL TEST
# ============================================================

if __name__ == "__main__":

    classifier = BERTClassifier()

    test_email = """
    Subject: Urgent Account Verification

    Your account will be suspended within 24 hours.
    Please click the link below and verify your password
    immediately to prevent account closure.
    """

    result = classifier.predict(
        test_email
    )

    print()
    print("TraceMail Fine-Tuned BERT")
    print("=========================")
    print(
        f"Classification: "
        f"{result['classification']}"
    )
    print(
        f"Confidence: "
        f"{result['confidence']}"
    )
    print(
        f"Model: "
        f"{result['model']}"
    )