from pathlib import Path

import numpy as np
import pandas as pd
import torch

from datasets import Dataset
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    DataCollatorWithPadding,
    Trainer,
    TrainingArguments,
)


# ============================================================
# CONFIGURATION
# ============================================================

MODEL_NAME = "distilbert-base-uncased"

DATA_DIR = Path("data/processed")

TRAIN_FILE = DATA_DIR / "train.csv"
VALIDATION_FILE = DATA_DIR / "validation.csv"

OUTPUT_DIR = Path(
    "app/ai/saved_model_smoke_test"
)

MAX_LENGTH = 128

NUM_LABELS = 2

LABEL_NAMES = {
    0: "BENIGN",
    1: "PHISHING",
}


# ============================================================
# DEVICE
# ============================================================

if torch.cuda.is_available():
    device = "cuda"
else:
    device = "cpu"

print("=" * 60)
print("TRACEMAIL BERT TRAINING")
print("=" * 60)

print(f"Device: {device}")

if device == "cuda":
    print(
        f"GPU: {torch.cuda.get_device_name(0)}"
    )
else:
    print(
        "GPU not detected. Training will use CPU."
    )


# ============================================================
# LOAD CSV FILES
# ============================================================

print("\nLoading datasets...")

train_df = pd.read_csv(TRAIN_FILE)

validation_df = pd.read_csv(
    VALIDATION_FILE
)

print(
    f"Training examples: "
    f"{len(train_df)}"
)

print(
    f"Validation examples: "
    f"{len(validation_df)}"
)

# ============================================================
# CPU SMOKE TEST
# ============================================================

# We first train on a small subset to verify that
# the complete training pipeline works correctly.
#
# After successful testing, these two blocks can be
# removed for full training.

train_df = train_df.sample(
    n=min(500, len(train_df)),
    random_state=42,
).reset_index(drop=True)

validation_df = validation_df.sample(
    n=min(100, len(validation_df)),
    random_state=42,
).reset_index(drop=True)

print("\nSmoke-test dataset:")
print(f"Training examples: {len(train_df)}")
print(f"Validation examples: {len(validation_df)}")
# ============================================================
# KEEP ONLY REQUIRED COLUMNS
# ============================================================

train_df = train_df[
    ["model_text", "label"]
].copy()

validation_df = validation_df[
    ["model_text", "label"]
].copy()


# ============================================================
# RENAME LABEL COLUMN
# ============================================================

train_df = train_df.rename(
    columns={
        "label": "labels"
    }
)

validation_df = validation_df.rename(
    columns={
        "label": "labels"
    }
)


# ============================================================
# CONVERT TO HUGGING FACE DATASETS
# ============================================================

train_dataset = Dataset.from_pandas(
    train_df,
    preserve_index=False,
)

validation_dataset = Dataset.from_pandas(
    validation_df,
    preserve_index=False,
)


# ============================================================
# LOAD TOKENIZER
# ============================================================

print("\nLoading tokenizer...")

tokenizer = AutoTokenizer.from_pretrained(
    MODEL_NAME
)


# ============================================================
# TOKENIZATION
# ============================================================

def tokenize_function(examples):

    return tokenizer(
        examples["model_text"],
        truncation=True,
        max_length=MAX_LENGTH,
    )


print("Tokenizing training data...")

tokenized_train = train_dataset.map(
    tokenize_function,
    batched=True,
    remove_columns=["model_text"],
)

print("Tokenizing validation data...")

tokenized_validation = validation_dataset.map(
    tokenize_function,
    batched=True,
    remove_columns=["model_text"],
)


# ============================================================
# DATA COLLATOR
# ============================================================

data_collator = DataCollatorWithPadding(
    tokenizer=tokenizer
)


# ============================================================
# LOAD MODEL
# ============================================================

print("\nLoading DistilBERT model...")

model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_NAME,
    num_labels=NUM_LABELS,
    id2label=LABEL_NAMES,
    label2id={
        "BENIGN": 0,
        "PHISHING": 1,
    },
)


# ============================================================
# TRAINING ARGUMENTS
# ============================================================

training_args = TrainingArguments(
    output_dir=str(OUTPUT_DIR),

    num_train_epochs=1,

    per_device_train_batch_size=8,
    per_device_eval_batch_size=8,

    learning_rate=2e-5,
    weight_decay=0.01,

    logging_strategy="steps",
    logging_steps=100,

    eval_strategy="epoch",
    save_strategy="epoch",

    save_total_limit=2,

    load_best_model_at_end=True,
    metric_for_best_model="eval_loss",
    greater_is_better=False,

    use_cpu=True,
    report_to="none",

    seed=42,
)


# ============================================================
# METRICS
# ============================================================

def compute_metrics(eval_prediction):

    predictions, labels = eval_prediction

    predictions = np.argmax(
        predictions,
        axis=1,
    )

    accuracy = (
        predictions == labels
    ).mean()

    return {
        "accuracy": float(accuracy)
    }


# ============================================================
# TRAINER
# ============================================================

trainer = Trainer(

    model=model,

    args=training_args,

    train_dataset=tokenized_train,

    eval_dataset=tokenized_validation,

    processing_class=tokenizer,

    data_collator=data_collator,

    compute_metrics=compute_metrics,
)


# ============================================================
# TRAIN
# ============================================================

print("\n" + "=" * 60)
print("STARTING FINE-TUNING")
print("=" * 60)

trainer.train()


# ============================================================
# FINAL VALIDATION
# ============================================================

print("\n" + "=" * 60)
print("VALIDATION RESULTS")
print("=" * 60)

results = trainer.evaluate()

for key, value in results.items():

    if isinstance(value, float):

        print(
            f"{key}: "
            f"{value:.4f}"
        )

    else:

        print(
            f"{key}: "
            f"{value}"
        )


# ============================================================
# SAVE FINAL MODEL
# ============================================================

print("\nSaving final model...")

trainer.save_model(
    OUTPUT_DIR
)

tokenizer.save_pretrained(
    OUTPUT_DIR
)


print("\n" + "=" * 60)
print("TRAINING COMPLETE")
print("=" * 60)

print(
    f"Model saved to: "
    f"{OUTPUT_DIR}"
)