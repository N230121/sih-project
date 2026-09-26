from pathlib import Path

import numpy as np
import pandas as pd
import torch
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


# ============================================================
# CONFIGURATION
# ============================================================

MODEL_DIR = Path("app/ai/saved_model_smoke_test")
TEST_FILE = Path("data/processed/test.csv")

MAX_LENGTH = 128

LABEL_NAMES = {
    0: "BENIGN",
    1: "PHISHING",
}


# ============================================================
# DEVICE
# ============================================================

device = "cuda" if torch.cuda.is_available() else "cpu"

print("=" * 60)
print("TRACEMAIL BERT EVALUATION")
print("=" * 60)

print(f"Device: {device}")


# ============================================================
# CHECK FILES
# ============================================================

if not MODEL_DIR.exists():
    raise FileNotFoundError(
        f"Trained model not found: {MODEL_DIR}"
    )

if not TEST_FILE.exists():
    raise FileNotFoundError(
        f"Test dataset not found: {TEST_FILE}"
    )


# ============================================================
# LOAD TEST DATA
# ============================================================

print("\nLoading test dataset...")

test_df = pd.read_csv(TEST_FILE)

print(f"Test examples: {len(test_df)}")
# ============================================================
# CPU EVALUATION SMOKE TEST
# ============================================================

test_df = test_df.sample(
    n=min(500, len(test_df)),
    random_state=42,
).reset_index(drop=True)

print(f"Smoke-test examples: {len(test_df)}")

required_columns = [
    "model_text",
    "label",
]

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

test_df["label"] = (
    pd.to_numeric(
        test_df["label"],
        errors="coerce",
    )
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
# CONVERT TO HUGGING FACE DATASET
# ============================================================

test_dataset = Dataset.from_pandas(
    test_df,
    preserve_index=False,
)

test_dataset = test_dataset.rename_column(
    "label",
    "labels",
)


# ============================================================
# LOAD TOKENIZER
# ============================================================

print("\nLoading tokenizer...")

tokenizer = AutoTokenizer.from_pretrained(
    MODEL_DIR
)


# ============================================================
# TOKENIZE TEST DATA
# ============================================================

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

print("Tokenization complete.")


# ============================================================
# LOAD TRAINED MODEL
# ============================================================

print("\nLoading trained model...")

model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_DIR
)

print("Model loaded successfully.")


# ============================================================
# CREATE TRAINER
# ============================================================

evaluation_args = TrainingArguments(
    output_dir="app/ai/evaluation_output",
    use_cpu=True,
    report_to="none",
)


trainer = Trainer(
    model=model,
    args=evaluation_args,
    processing_class=tokenizer,
)


# ============================================================
# RUN PREDICTIONS
# ============================================================

print("\n" + "=" * 60)
print("RUNNING PREDICTIONS")
print("=" * 60)

prediction_output = trainer.predict(
    tokenized_test
)

logits = prediction_output.predictions

predictions = np.argmax(
    logits,
    axis=1,
)

actual_labels = prediction_output.label_ids


# ============================================================
# BASIC METRICS
# ============================================================

accuracy = accuracy_score(
    actual_labels,
    predictions,
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
# PRINT METRICS
# ============================================================

print("\n" + "=" * 60)
print("EVALUATION RESULTS")
print("=" * 60)

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
    labels=[0, 1],
)

print("\n" + "=" * 60)
print("CONFUSION MATRIX")
print("=" * 60)

print("\n                Predicted")
print("              BENIGN  PHISHING")
print(
    f"Actual BENIGN   {matrix[0][0]:6d}  {matrix[0][1]:8d}"
)
print(
    f"Actual PHISHING {matrix[1][0]:6d}  {matrix[1][1]:8d}"
)


# ============================================================
# CLASSIFICATION REPORT
# ============================================================

print("\n" + "=" * 60)
print("CLASSIFICATION REPORT")
print("=" * 60)

print(
    classification_report(
        actual_labels,
        predictions,
        labels=[0, 1],
        target_names=[
            "BENIGN",
            "PHISHING",
        ],
        zero_division=0,
    )
)


# ============================================================
# PREDICTION DISTRIBUTION
# ============================================================

print("=" * 60)
print("PREDICTION DISTRIBUTION")
print("=" * 60)

prediction_counts = pd.Series(
    predictions
).value_counts().sort_index()

# ============================================================
# ERROR ANALYSIS
# ============================================================

print("\n" + "=" * 60)
print("ERROR ANALYSIS")
print("=" * 60)

results_df = test_df.copy()

results_df["actual"] = actual_labels
results_df["predicted"] = predictions

false_positives = results_df[
    (results_df["actual"] == 0)
    & (results_df["predicted"] == 1)
]

false_negatives = results_df[
    (results_df["actual"] == 1)
    & (results_df["predicted"] == 0)
]

print(f"\nFalse Positives: {len(false_positives)}")
print(f"False Negatives: {len(false_negatives)}")

print("\n--- Sample False Positives ---")

for index, row in false_positives.head(3).iterrows():
    print("\nEmail:")
    print(row["model_text"][:500])

print("\n--- Sample False Negatives ---")

for index, row in false_negatives.head(3).iterrows():
    print("\nEmail:")
    print(row["model_text"][:500])

for label_id, count in prediction_counts.items():
    label_name = LABEL_NAMES[int(label_id)]

    print(
        f"{label_name}: {count}"
    )


print("\n" + "=" * 60)
print("3E EVALUATION COMPLETE")
print("=" * 60)