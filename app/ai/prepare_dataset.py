from pathlib import Path

import pandas as pd
from datasets import load_dataset


# ============================================================
# CONFIGURATION
# ============================================================

DATASET_NAME = "puyang2025/seven-phishing-email-datasets"

OUTPUT_DIR = Path("data/processed")

OUTPUT_FILE = OUTPUT_DIR / "phishing_email_dataset.csv"


# ============================================================
# LOAD DATASET
# ============================================================

print("=" * 60)
print("LOADING DATASET")
print("=" * 60)

dataset = load_dataset(DATASET_NAME)

df = dataset["train"].to_pandas()

print(f"Original rows: {len(df)}")


# ============================================================
# KEEP ONLY REQUIRED COLUMNS
# ============================================================

required_columns = [
    "text",
    "subject",
    "label",
    "dataset_name",
]

missing_columns = [
    column
    for column in required_columns
    if column not in df.columns
]

if missing_columns:
    raise ValueError(
        f"Missing columns: {missing_columns}"
    )

df = df[required_columns].copy()


# ============================================================
# NORMALIZE MISSING VALUES
# ============================================================

print("\nNormalizing missing values...")

df["text"] = df["text"].fillna("").astype(str)
df["subject"] = df["subject"].fillna("").astype(str)
df["dataset_name"] = (
    df["dataset_name"]
    .fillna("unknown")
    .astype(str)
)


# ============================================================
# CLEAN WHITESPACE
# ============================================================

print("Cleaning whitespace...")

df["text"] = (
    df["text"]
    .str.replace(r"\s+", " ", regex=True)
    .str.strip()
)

df["subject"] = (
    df["subject"]
    .str.replace(r"\s+", " ", regex=True)
    .str.strip()
)


# ============================================================
# REMOVE EMAILS WITH NO BODY AND NO SUBJECT
# ============================================================

print("\nRemoving empty emails...")

before = len(df)

df = df[
    (df["text"].str.len() > 0)
    | (df["subject"].str.len() > 0)
].copy()

removed_empty = before - len(df)

print(f"Removed empty emails: {removed_empty}")


# ============================================================
# NORMALIZE LABELS
# ============================================================

print("\nNormalizing labels...")

df["label"] = pd.to_numeric(
    df["label"],
    errors="coerce"
)

df = df[df["label"].isin([0, 1])].copy()

df["label"] = df["label"].astype(int)


# ============================================================
# CONSTRUCT MODEL INPUT
# ============================================================

print("\nConstructing BERT input text...")

def build_model_text(row):
    subject = row["subject"]
    body = row["text"]

    if subject:
        return f"Subject: {subject}\n\n{body}"

    return body


df["model_text"] = df.apply(
    build_model_text,
    axis=1,
)


# ============================================================
# REMOVE EXACT DUPLICATES
# ============================================================

print("\nRemoving exact duplicate emails...")

before = len(df)

df = df.drop_duplicates(
    subset=["model_text", "label"]
).copy()

removed_duplicates = before - len(df)

print(
    f"Removed exact duplicates: "
    f"{removed_duplicates}"
)


# ============================================================
# HANDLE SAME EMAIL WITH DIFFERENT LABELS
# ============================================================

print("\nChecking conflicting labels...")

label_counts = (
    df.groupby("model_text")["label"]
    .nunique()
)

conflicting_texts = label_counts[
    label_counts > 1
].index

print(
    f"Emails with conflicting labels: "
    f"{len(conflicting_texts)}"
)

if len(conflicting_texts) > 0:

    df = df[
        ~df["model_text"].isin(conflicting_texts)
    ].copy()

    print(
        "Removed conflicting examples."
    )


# ============================================================
# SELECT FINAL COLUMNS
# ============================================================

df = df[
    [
        "model_text",
        "label",
        "dataset_name",
    ]
].copy()


# ============================================================
# SHUFFLE
# ============================================================

df = df.sample(
    frac=1,
    random_state=42,
).reset_index(drop=True)


# ============================================================
# FINAL STATISTICS
# ============================================================

print("\n" + "=" * 60)
print("FINAL DATASET")
print("=" * 60)

print(f"Total rows: {len(df)}")

print("\nLabel distribution:")

print(
    df["label"]
    .value_counts()
    .sort_index()
)

print("\nSource distribution:")

print(
    df["dataset_name"]
    .value_counts()
)


# ============================================================
# SAVE
# ============================================================

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

df.to_csv(
    OUTPUT_FILE,
    index=False,
)

print("\n" + "=" * 60)
print("DATASET SAVED")
print("=" * 60)

print(f"File: {OUTPUT_FILE}")
print(f"Rows: {len(df)}")