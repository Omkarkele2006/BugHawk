from datasets import load_dataset


ds = load_dataset("Addyk24/code_maintainence")

# Check your original dataset for mislabeling
# Look for these patterns in your training data:

# Check your original dataset for mislabeling
# Look for these patterns in your training data:

# Get more detailed statistics
import collections

print("=== DATASET STATISTICS ===")
labels = [ex['labels'] for ex in ds["data"]]
label_counts = collections.Counter(labels)
print(f"Total examples: {len(ds["data"])}")
print(f"Label distribution: {dict(label_counts)}")
print(f"Debug percentage: {label_counts[0]/len(ds["data"])*100:.1f}%")
print(f"Threat percentage: {label_counts[1]/len(ds["data"])*100:.1f}%")

# Check average text length
debug_texts = [ex['problem'] for ex in ds["data"] if ex['labels'] == 0]
threat_texts = [ex['problem'] for ex in ds["data"] if ex['labels'] == 1]

print(f"\nAverage debug text length: {sum(len(t.split()) for t in debug_texts)/len(debug_texts):.1f} words")
print(f"Average threat text length: {sum(len(t.split()) for t in threat_texts)/len(threat_texts):.1f} words")