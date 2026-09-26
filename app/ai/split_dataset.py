from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split


# ============================================================
# CONFIGURATION
# ============================================================

INPUT_FILE = Path(
    "data/processed/phishing_email_dataset.csv"
)

OUTPUT_DIR = Path(
    "data/processed"
)

RANDOM_STATE = 42


# ============================================================
# LOAD DATASET
# ============================================================

print("=" * 60)
print("LOADING PROCESSED DATASET")
print("=" * 60)

df = pd.read_csv(INPUT_FILE)

print(f"Total rows: {len(df)}")


# ============================================================
# CHECK REQUIRED COLUMNS
# ============================================================

required_columns = [
    "model_text",
    "label",
    "dataset_name",
]

missing = [
    column
    for column in required_columns
    if column not in df.columns
]

if missing:
    raise ValueError(
        f"Missing required columns: {missing}"
    )


# ============================================================
# ORIGINAL LABEL DISTRIBUTION
# ============================================================

print("\nOriginal label distribution:")

print(
    df["label"]
    .value_counts()
    .sort_index()
)


# ============================================================
# FIRST SPLIT
# 80% TRAIN
# 20% TEMPORARY
# ============================================================

train_df, temp_df = train_test_split(
    df,
    test_size=0.20,
    random_state=RANDOM_STATE,
    stratify=df["label"],
)


# ============================================================
# SECOND SPLIT
# HALF VALIDATION
# HALF TEST
#
# 20% temporary
#      ↓
# 10% validation
# 10% test
# ============================================================

validation_df, test_df = train_test_split(
    temp_df,
    test_size=0.50,
    random_state=RANDOM_STATE,
    stratify=temp_df["label"],
)


# ============================================================
# SHUFFLE EACH SPLIT
# ============================================================

train_df = train_df.sample(
    frac=1,
    random_state=RANDOM_STATE,
).reset_index(drop=True)

validation_df = validation_df.sample(
    frac=1,
    random_state=RANDOM_STATE,
).reset_index(drop=True)

test_df = test_df.sample(
    frac=1,
    random_state=RANDOM_STATE,
).reset_index(drop=True)


# ============================================================
# SAVE
# ============================================================

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

train_file = OUTPUT_DIR / "train.csv"
validation_file = OUTPUT_DIR / "validation.csv"
test_file = OUTPUT_DIR / "test.csv"

train_df.to_csv(
    train_file,
    index=False,
)

validation_df.to_csv(
    validation_file,
    index=False,
)

test_df.to_csv(
    test_file,
    index=False,
)


# ============================================================
# REPORT
# ============================================================

print("\n" + "=" * 60)
print("DATASET SPLIT COMPLETE")
print("=" * 60)

print(f"\nTrain:      {len(train_df)}")
print(f"Validation: {len(validation_df)}")
print(f"Test:       {len(test_df)}")


print("\nTrain label distribution:")
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


print("\nTest label distribution:")
print(
    test_df["label"]
    .value_counts()
    .sort_index()
)


# ============================================================
# PERCENTAGES
# ============================================================

total = len(df)

print("\nSplit percentages:")

print(
    f"Train:      {len(train_df) / total * 100:.2f}%"
)

print(
    f"Validation: {len(validation_df) / total * 100:.2f}%"
)

print(
    f"Test:       {len(test_df) / total * 100:.2f}%"
)


# ============================================================
# FINAL FILES
# ============================================================

print("\nFiles created:")

print(train_file)
print(validation_file)
print(test_file)

print("\nPhase 3C.6 COMPLETE")