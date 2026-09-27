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
    "app/ai/saved_model_finetuned"
)

MAX_LENGTH = 128

NUM_LABELS = 2

LABEL_NAMES = {
    0: "BENIGN",
    1: "PHISHING",
}

RANDOM_SEED = 42


# ============================================================
# DEVICE
# ============================================================

if torch.cuda.is_available():

    device = "cuda"

else:

    device = "cpu"


print("=" * 70)
print("TRACEMAIL BERT FULL FINE-TUNING")
print("=" * 70)

print(f"Device: {device}")

if device == "cuda":

    print(
        f"GPU: {torch.cuda.get_device_name(0)}"
    )

else:

    print(
        "WARNING: CUDA GPU not detected."
    )

    print(
        "Full training on CPU may take a very long time."
    )


# ============================================================
# CHECK DATASET FILES
# ============================================================

if not TRAIN_FILE.exists():

    raise FileNotFoundError(
        f"Training file not found: {TRAIN_FILE}"
    )


if not VALIDATION_FILE.exists():

    raise FileNotFoundError(
        f"Validation file not found: {VALIDATION_FILE}"
    )


# ============================================================
# LOAD DATASETS
# ============================================================

print("\n" + "=" * 70)
print("LOADING DATASETS")
print("=" * 70)

train_df = pd.read_csv(
    TRAIN_FILE
)

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
# CHECK REQUIRED COLUMNS
# ============================================================

required_columns = [
    "model_text",
    "label",
]

for column in required_columns:

    if column not in train_df.columns:

        raise ValueError(
            f"Missing column in training dataset: {column}"
        )

    if column not in validation_df.columns:

        raise ValueError(
            f"Missing column in validation dataset: {column}"
        )


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
# CLEAN DATA TYPES
# ============================================================

train_df["model_text"] = (
    train_df["model_text"]
    .fillna("")
    .astype(str)
)

validation_df["model_text"] = (
    validation_df["model_text"]
    .fillna("")
    .astype(str)
)

train_df["label"] = pd.to_numeric(
    train_df["label"],
    errors="coerce",
)

validation_df["label"] = pd.to_numeric(
    validation_df["label"],
    errors="coerce",
)


# ============================================================
# REMOVE INVALID LABELS
# ============================================================

train_df = train_df[
    train_df["label"].isin([0, 1])
].copy()

validation_df = validation_df[
    validation_df["label"].isin([0, 1])
].copy()


train_df["label"] = train_df["label"].astype(int)

validation_df["label"] = validation_df["label"].astype(int)


# ============================================================
# DISPLAY DISTRIBUTION
# ============================================================

print("\nTraining label distribution:")

print(
    train_df["label"]
    .value_counts()
    .sort_index()
)


print("\nValidation label distribution:")

print(
    validation_df["label"]
    .value_counts()
    .sort_index()
)


# ============================================================
# CONVERT TO HUGGING FACE DATASETS
# ============================================================

print("\nConverting datasets...")

train_dataset = Dataset.from_pandas(
    train_df,
    preserve_index=False,
)

validation_dataset = Dataset.from_pandas(
    validation_df,
    preserve_index=False,
)


# ============================================================
# RENAME LABEL COLUMN
# ============================================================

train_dataset = train_dataset.rename_column(
    "label",
    "labels",
)

validation_dataset = validation_dataset.rename_column(
    "label",
    "labels",
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


print("Tokenizing training dataset...")

tokenized_train = train_dataset.map(
    tokenize_function,
    batched=True,
    remove_columns=["model_text"],
)


print("Tokenizing validation dataset...")

tokenized_validation = validation_dataset.map(
    tokenize_function,
    batched=True,
    remove_columns=["model_text"],
)


print("Tokenization complete.")


# ============================================================
# DATA COLLATOR
# ============================================================

data_collator = DataCollatorWithPadding(
    tokenizer=tokenizer
)


# ============================================================
# LOAD DISTILBERT
# ============================================================

print("\nLoading DistilBERT...")

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

    num_train_epochs=2,

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

    report_to="none",

    seed=RANDOM_SEED,

    fp16=(
        True
        if device == "cuda"
        else False
    ),

    use_cpu=(
        True
        if device == "cpu"
        else False
    ),
)


# ============================================================
# METRICS
# ============================================================

def compute_metrics(
    eval_prediction
):

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
# START TRAINING
# ============================================================

print("\n" + "=" * 70)
print("STARTING FULL FINE-TUNING")
print("=" * 70)

print(
    f"Training examples: {len(tokenized_train)}"
)

print(
    f"Validation examples: "
    f"{len(tokenized_validation)}"
)

print(
    f"Epochs: "
    f"{training_args.num_train_epochs}"
)

print(
    f"Batch size: "
    f"{training_args.per_device_train_batch_size}"
)

print(
    f"Maximum sequence length: "
    f"{MAX_LENGTH}"
)


trainer.train()


# ============================================================
# FINAL VALIDATION
# ============================================================

print("\n" + "=" * 70)
print("FINAL VALIDATION")
print("=" * 70)

validation_results = trainer.evaluate()

for key, value in validation_results.items():

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
# SAVE BEST MODEL
# ============================================================

print("\n" + "=" * 70)
print("SAVING FINE-TUNED MODEL")
print("=" * 70)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

trainer.save_model(
    OUTPUT_DIR
)

tokenizer.save_pretrained(
    OUTPUT_DIR
)


print(
    f"\nModel saved to:\n"
    f"{OUTPUT_DIR}"
)


print("\n" + "=" * 70)
print("BERT FINE-TUNING COMPLETE")
print("=" * 70)