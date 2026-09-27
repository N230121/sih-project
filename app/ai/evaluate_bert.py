from pathlib import Path

import numpy as np
import pandas as pd
from datasets import Dataset
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    classification_report,
)
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    Trainer,
    TrainingArguments,
)

MODEL_DIR = Path("app/ai/saved_model_finetuned")
TEST_FILE = Path("data/processed/test.csv")
MAX_LENGTH = 128
LABEL_NAMES = {0: "BENIGN", 1: "PHISHING"}

print("=" * 70)
print("TRACEMAIL BERT FINAL EVALUATION")
print("=" * 70)

if not MODEL_DIR.exists():
    raise FileNotFoundError(
        f"Fine-tuned model not found: {MODEL_DIR}"
    )

if not TEST_FILE.exists():
    raise FileNotFoundError(
        f"Test dataset not found: {TEST_FILE}"
    )

print("\nLoading complete test dataset...")

test_df = pd.read_csv(TEST_FILE)

print(f"Test examples loaded: {len(test_df)}")

required_columns = ["model_text", "label"]

missing_columns = [
    column
    for column in required_columns
    if column not in test_df.columns
]

if missing_columns:
    raise ValueError(
        f"Missing required columns: {missing_columns}"
    )

test_df = test_df[
    ["model_text", "label"]
].copy()

test_df["model_text"] = (
    test_df["model_text"]
    .fillna("")
    .astype(str)
)

test_df["label"] = pd.to_numeric(
    test_df["label"],
    errors="coerce"
)

test_df = test_df[
    test_df["label"].isin([0, 1])
].copy()

test_df["label"] = test_df["label"].astype(int)

print(f"Valid test examples: {len(test_df)}")

print("\nTest label distribution:")
print(
    test_df["label"]
    .value_counts()
    .sort_index()
)


# ============================================================
# CONVERT TO DATASET
# ============================================================

test_dataset = Dataset.from_pandas(
    test_df,
    preserve_index=False
)

test_dataset = test_dataset.rename_column(
    "label",
    "labels"
)


# ============================================================
# TOKENIZER
# ============================================================

print("\nLoading fine-tuned tokenizer...")

tokenizer = AutoTokenizer.from_pretrained(
    MODEL_DIR
)


def tokenize_function(examples):
    return tokenizer(
        examples["model_text"],
        truncation=True,
        max_length=MAX_LENGTH,
    )


print("Tokenizing test dataset...")

tokenized_test = test_dataset.map(
    tokenize_function,
    batched=True,
    remove_columns=["model_text"],
)

print("Test tokenization complete.")


# ============================================================
# MODEL
# ============================================================

print("\nLoading fine-tuned model...")

model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_DIR
)

print("Fine-tuned model loaded successfully.")


# ============================================================
# EVALUATION CONFIG
# ============================================================

evaluation_args = TrainingArguments(
    output_dir="app/ai/evaluation_output",
    report_to="none",
)


trainer = Trainer(
    model=model,
    args=evaluation_args,
    processing_class=tokenizer,
)


# ============================================================
# PREDICTION
# ============================================================

print("\n" + "=" * 70)
print("RUNNING FINAL TEST PREDICTIONS")
print("=" * 70)

prediction_output = trainer.predict(
    tokenized_test
)

logits = prediction_output.predictions

predictions = np.argmax(
    logits,
    axis=1
)

actual_labels = prediction_output.label_ids


# ============================================================
# METRICS
# ============================================================

accuracy = accuracy_score(
    actual_labels,
    predictions
)

precision, recall, f1, _ = (
    precision_recall_fscore_support(
        actual_labels,
        predictions,
        average="binary",
        zero_division=0,
    )
)


# ============================================================
# FINAL RESULTS
# ============================================================

print("\n" + "=" * 70)
print("FINAL BERT RESULTS")
print("=" * 70)

print(f"\nAccuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1 Score : {f1:.4f}")


# ============================================================
# CONFUSION MATRIX
# ============================================================

matrix = confusion_matrix(
    actual_labels,
    predictions,
    labels=[0, 1]
)

print("\n" + "=" * 70)
print("CONFUSION MATRIX")
print("=" * 70)

print("\n                    Predicted")
print("                 BENIGN  PHISHING")

print(
    f"Actual BENIGN     "
    f"{matrix[0][0]:6d}  "
    f"{matrix[0][1]:8d}"
)

print(
    f"Actual PHISHING   "
    f"{matrix[1][0]:6d}  "
    f"{matrix[1][1]:8d}"
)


# ============================================================
# CLASSIFICATION REPORT
# ============================================================

print("\n" + "=" * 70)
print("CLASSIFICATION REPORT")
print("=" * 70)

print(
    classification_report(
        actual_labels,
        predictions,
        labels=[0, 1],
        target_names=[
            "BENIGN",
            "PHISHING"
        ],
        zero_division=0,
    )
)


# ============================================================
# ERROR ANALYSIS
# ============================================================

print("\n" + "=" * 70)
print("ERROR ANALYSIS")
print("=" * 70)

results_df = test_df.copy()

results_df["actual"] = actual_labels
results_df["predicted"] = predictions


false_positives = results_df[
    (results_df["actual"] == 0)
    &
    (results_df["predicted"] == 1)
]

false_negatives = results_df[
    (results_df["actual"] == 1)
    &
    (results_df["predicted"] == 0)
]


print(
    f"\nFalse Positives: "
    f"{len(false_positives)}"
)

print(
    f"False Negatives: "
    f"{len(false_negatives)}"
)


print("\n--- Sample False Positives ---")

for _, row in false_positives.head(5).iterrows():

    print("\nEmail:")

    print(
        row["model_text"][:700]
    )


print("\n--- Sample False Negatives ---")

for _, row in false_negatives.head(5).iterrows():

    print("\nEmail:")

    print(
        row["model_text"][:700]
    )


# ============================================================
# PREDICTION DISTRIBUTION
# ============================================================

print("\n" + "=" * 70)
print("PREDICTION DISTRIBUTION")
print("=" * 70)

prediction_counts = (
    pd.Series(predictions)
    .value_counts()
    .sort_index()
)

for label_id, count in prediction_counts.items():

    label_name = LABEL_NAMES[
        int(label_id)
    ]

    print(
        f"{label_name}: {count}"
    )


print("\n" + "=" * 70)
print("3E FINAL EVALUATION COMPLETE")
print("=" * 70)