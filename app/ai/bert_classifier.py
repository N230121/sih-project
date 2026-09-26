from typing import Dict

import torch
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
)


MODEL_NAME = "distilbert-base-uncased"


class BERTClassifier:
    """
    Phase 3B baseline NLP classifier.

    IMPORTANT:
    This model is pretrained but NOT fine-tuned for
    TraceMail yet.

    It is currently only a baseline/test model.
    """

    def __init__(self):
        self.tokenizer = AutoTokenizer.from_pretrained(
            MODEL_NAME
        )

        self.model = AutoModelForSequenceClassification.from_pretrained(
            MODEL_NAME,
            num_labels=2,
        )

        self.model.eval()

        self.labels = {
            0: "BENIGN",
            1: "PHISHING",
        }

    def predict(self, text: str) -> Dict:
        """
        Run a baseline prediction on email text.
        """

        if not text or not text.strip():
            return {
                "classification": "UNKNOWN",
                "confidence": 0.0,
                "note": "No email text supplied.",
            }

        inputs = self.tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
        )

        with torch.no_grad():
            outputs = self.model(**inputs)

        probabilities = torch.softmax(
            outputs.logits,
            dim=-1,
        )[0]

        predicted_id = int(
            torch.argmax(probabilities).item()
        )

        confidence = float(
            probabilities[predicted_id].item()
        )

        return {
            "classification": self.labels[predicted_id],
            "confidence": round(confidence, 4),
        }


if __name__ == "__main__":

    classifier = BERTClassifier()

    test_email = """
    Subject: Urgent Account Verification

    Your account will be suspended within 24 hours.
    Please click the link below and verify your password
    immediately to prevent account closure.
    """

    result = classifier.predict(test_email)

    print("TraceMail BERT Baseline")
    print("-----------------------")
    print(f"Classification: {result['classification']}")
    print(f"Confidence: {result['confidence']}")