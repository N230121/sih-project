from collections import Counter

from datasets import load_dataset


DATASET_NAME = "puyang2025/seven-phishing-email-datasets"


print("Loading dataset...")
dataset = load_dataset(DATASET_NAME)

data = dataset["train"]

print("\n========================================")
print("DATASET INFORMATION")
print("========================================")

print(f"Total rows: {len(data)}")
print(f"Columns: {data.column_names}")


# ------------------------------------------------------------
# LABEL DISTRIBUTION
# ------------------------------------------------------------

print("\n========================================")
print("LABEL DISTRIBUTION")
print("========================================")

labels = data["label"]
label_counts = Counter(labels)

for label, count in sorted(label_counts.items()):
    print(f"Label {label}: {count}")


# ------------------------------------------------------------
# SOURCE DISTRIBUTION
# ------------------------------------------------------------

print("\n========================================")
print("SOURCE DISTRIBUTION")
print("========================================")

sources = data["dataset_name"]
source_counts = Counter(sources)

for source, count in source_counts.most_common():
    print(f"{source}: {count}")


# ------------------------------------------------------------
# MISSING / EMPTY VALUES
# ------------------------------------------------------------

print("\n========================================")
print("EMPTY EMAIL ANALYSIS")
print("========================================")

empty_text = 0
empty_subject = 0

for row in data:
    text = row.get("text")
    subject = row.get("subject")

    if not text or not str(text).strip():
        empty_text += 1

    if not subject or not str(subject).strip():
        empty_subject += 1

print(f"Empty body: {empty_text}")
print(f"Empty subject: {empty_subject}")


# ------------------------------------------------------------
# SAMPLE EMAILS
# ------------------------------------------------------------

print("\n========================================")
print("SAMPLE EMAILS")
print("========================================")

for index in [0, 1, 2, 100, 1000]:

    if index >= len(data):
        continue

    row = data[index]

    print(f"\n--- SAMPLE {index} ---")
    print(f"Label: {row.get('label')}")
    print(f"Source: {row.get('dataset_name')}")
    print(f"Subject: {row.get('subject')}")

    text = row.get("text") or ""

    print("Body:")
    print(str(text)[:500])


# ------------------------------------------------------------
# EXACT DUPLICATES
# ------------------------------------------------------------

print("\n========================================")
print("DUPLICATE ANALYSIS")
print("========================================")

texts = []

for row in data:
    subject = str(row.get("subject") or "").strip()
    text = str(row.get("text") or "").strip()

    combined = f"{subject}\n{text}"

    texts.append(combined)

unique_count = len(set(texts))
duplicate_count = len(texts) - unique_count

print(f"Total emails: {len(texts)}")
print(f"Unique emails: {unique_count}")
print(f"Exact duplicate rows: {duplicate_count}")


print("\n========================================")
print("ANALYSIS COMPLETE")
print("========================================")