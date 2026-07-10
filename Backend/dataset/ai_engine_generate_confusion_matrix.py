import pandas as pd
import numpy as np
import torch
import glob
import os
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report
from transformers import AutoTokenizer, AutoModelForSequenceClassification, Trainer
from torch.utils.data import Dataset

# --- 1. SETUP & CLASSES (Must match train_model.py) ---

class BugHawkDataset(Dataset):
    def __init__(self, encodings, labels):
        self.encodings = encodings
        self.labels = labels

    def __getitem__(self, idx):
        item = {key: torch.tensor(val[idx]) for key, val in self.encodings.items()}
        item['labels'] = torch.tensor(self.labels[idx])
        return item

    def __len__(self):
        return len(self.labels)

def get_latest_checkpoint(results_dir='./results'):
    """Finds the latest checkpoint folder from training"""
    checkpoints = glob.glob(os.path.join(results_dir, 'checkpoint-*'))
    if not checkpoints:
        return None
    # Sort by step number (checkpoint-500, checkpoint-1000)
    latest_checkpoint = max(checkpoints, key=lambda x: int(x.split('-')[-1]))
    return latest_checkpoint

# --- 2. MAIN GENERATION LOGIC ---

def generate_matrix():
    print("📊 Starting Confusion Matrix Generation...")

    # A. Load Data
    data_path = "bughawk_training_data.csv"
    if not os.path.exists(data_path):
        print(f"❌ Error: {data_path} not found. Run train_model.py first.")
        return

    df = pd.read_csv(data_path)
    # Re-create validation split (Stratified to maintain class balance)
    _, val_texts, _, val_labels = train_test_split(
        df['problem'].tolist(), df['label'].tolist(), test_size=0.2, stratify=df['label'], random_state=42
    )

    print(f"Loaded {len(val_texts)} validation samples.")

    # B. Load Model
    checkpoint = get_latest_checkpoint()
    model_path = checkpoint if checkpoint else "distilbert-base-uncased"
    
    print(f"Loading model from: {model_path}")
    
    try:
        tokenizer = AutoTokenizer.from_pretrained(model_path)
        model = AutoModelForSequenceClassification.from_pretrained(model_path, num_labels=2)
    except Exception as e:
        print(f"⚠️ Could not load trained model ({e}). Using base model for demonstration.")
        tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")
        model = AutoModelForSequenceClassification.from_pretrained("distilbert-base-uncased", num_labels=2)

    # C. Tokenize & Predict
    val_encodings = tokenizer(val_texts, truncation=True, padding=True, max_length=128)
    val_dataset = BugHawkDataset(val_encodings, val_labels)

    trainer = Trainer(model=model)
    
    print("🧠 Running Inference on Validation Set...")
    predictions = trainer.predict(val_dataset)
    
    # Get predicted classes (0 or 1)
    y_preds = np.argmax(predictions.predictions, axis=1)
    y_true = predictions.label_ids

    # D. Create Confusion Matrix
    cm = confusion_matrix(y_true, y_preds)
    
    # Extract TP, TN, FP, FN
    tn, fp, fn, tp = cm.ravel()
    
    # Print Metrics for Paper
    print("\n" + "="*40)
    print("   BUGHAWK MODEL PERFORMANCE REPORT   ")
    print("="*40)
    print(classification_report(y_true, y_preds, target_names=['Debug (0)', 'Threat (1)']))
    print(f"True Positives (Caught Threats): {tp}")
    print(f"False Negatives (Missed Threats): {fn}")
    print("="*40 + "\n")

    # E. Plotting
    plt.figure(figsize=(8, 6))
    
    # Custom Labels
    labels = ['Debug (0)', 'Threat (1)']
    
    # Heatmap
    sns.set(font_scale=1.2)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=labels, yticklabels=labels,
                linewidths=2, linecolor='white', cbar=False)

    plt.title('BugHawk Hybrid Engine: Confusion Matrix', fontsize=16, fontweight='bold', pad=20)
    plt.xlabel('Predicted Label', fontsize=12, fontweight='bold')
    plt.ylabel('Actual Label', fontsize=12, fontweight='bold')

    # Save
    output_filename = 'bughawk_confusion_matrix.png'
    plt.tight_layout()
    plt.savefig(output_filename, dpi=300)
    print(f"✅ Confusion Matrix saved to: {output_filename}")
    plt.show()

if __name__ == "__main__":
    generate_matrix()