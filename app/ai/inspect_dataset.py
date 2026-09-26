from datasets import load_dataset


DATASET_NAME = "puyang2025/seven-phishing-email-datasets"


print("Loading dataset...")
dataset = load_dataset(DATASET_NAME)

print("\nDataset loaded.")
print(dataset)

train = dataset["train"]

print("\nNumber of rows:")
print(len(train))

print("\nColumns:")
print(train.column_names)

print("\nFirst example:")
print(train[0])