import torch
import torch.nn as nn
from transformers import AutoModelForSequenceClassification, AutoTokenizer, EarlyStoppingCallback
from transformers import Trainer, TrainingArguments
from sklearn.metrics import accuracy_score, f1_score, classification_report
from sklearn.utils.class_weight import compute_class_weight
from torch.utils.data import Dataset
from typing import Dict, Optional
import os
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

ds = None
model_path = "distilbert/distilbert-base-uncased"
fine_tuned_model_path = "Addyk24/ThreatScan"


class IntentClassifier:
    def __init__(self):
        self.model_path = fine_tuned_model_path
        
        # Load tokenizer from cache first
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True)
        except Exception:
            try:
                self.tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=False, timeout=15)
            except Exception:
                self.tokenizer = None
                
        self.model = None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.label_mapping = {
            "debug" : 0,
            "threat" : 1
        }
        self.id2label = {v: k for k, v in self.label_mapping.items()}

    def load_model(self, model_path = fine_tuned_model_path):
        """ Loading of Finetuned Model """
        path_to_use = model_path if model_path else self.model_path

        try:
            self.model = AutoModelForSequenceClassification.from_pretrained(path_to_use, local_files_only=True)
        except Exception:
            self.model = AutoModelForSequenceClassification.from_pretrained(path_to_use, local_files_only=False, timeout=15)

        self.model.to(self.device)
        self.model.eval()

    def process_text(self,text,max_length=256):
        """ Preprocess and Tokenize of text """

        # Normalize input into list of strings
        if isinstance(text, dict):
            if "problem" in text:
                texts = [text["problem"]]
            else:
                raise ValueError("Dict input must contain 'problem' key")
        elif isinstance(text, list):
            texts = [t["problem"] if isinstance(t, dict) else t for t in text]
        else:
            texts = [str(text)]

        # Preprocess text (lowercase and strip whitespace)
        texts = [t.lower().strip() for t in texts]

        # Tokenize text
        tokenized_input = self.tokenizer(
            texts,
            padding=True,
            truncation=True,
            max_length=max_length,
            return_tensors="pt"
        )
        return tokenized_input
    
    def predict(self, text: str) -> Dict:
        """ Predict the intent of input text """
        if self.model is None:
            raise ValueError("Model not loaded. Call load_model() first.")
        
        # Tokenize text
        tokenized_input = self.process_text(text)
        tokenized_input = {k: v.to(self.device) for k, v in tokenized_input.items()}

        # Predict
        with torch.no_grad():
            outputs = self.model(**tokenized_input)
            logits = outputs.logits
            # probability
            predicted_value = torch.softmax(logits,dim=-1)

        prediction_class = torch.argmax(predicted_value,dim=-1).item()
        confidence = predicted_value[0][prediction_class].item()

        return {
            "Problem_type" : self.id2label[prediction_class],
            "confidence" : float(confidence) 
        }
    

class IntentClassifierTrainer:
    def __init__(self, dataset=None):
        self.classifier = IntentClassifier()
        if dataset is None:
            global ds
            if ds is None:
                from datasets import load_dataset
                ds = load_dataset("Addyk24/code_threat_maintance")
            self.ds = ds
        else:
            self.ds = dataset
        
    def encode_labels(self,datapoint):
        datapoint["labels"] = int(self.classifier.label_mapping[datapoint["label"]])
        return datapoint
    

    def normalize_data(Self,datapoint):
        datapoint["label"] = datapoint["label"].lower()
        return datapoint

    def prepare_dataset(self):
        """ Prepare dataset for training proper label mapping """
        dataset = self.ds.train_test_split(
            test_size=0.2,
            random_state=42
        )

        train_ds = dataset["train"]
        test_ds = dataset["test"]
        train_ds = train_ds.map(self.classifier.process_text,batched=True,remove_columns=["problem"])
        test_ds = test_ds.map(self.classifier.process_text,batched=True,remove_columns=["problem"])
        
        train_ds.set_format(type="torch",columns=["input_ids","attention_mask","labels"])
        test_ds.set_format(type="torch",columns=["input_ids","attention_mask","labels"])

        return train_ds,test_ds
    
    def calculate_class_weights(self, train_ds):
        """ Calculate class weights to handle class imbalance """
        labels = np.array(train_ds['labels'])
        class_weights = compute_class_weight(
            class_weight="balanced",
            classes=np.unique(labels),
            y=labels
        )
        return torch.tensor(class_weights,dtype=torch.float)

    
    def train_model(self,train_ds,test_ds,output_dir="trained_models/intent_classifier"):
        """ Training details """

        # Calculate class weights
        class_weights = self.calculate_class_weights(train_ds)
        class_weights = class_weights.to(self.classifier.device)

        # Custom Trainer class to support class weights in loss calculation
        class CustomTrainer(Trainer):
            def compute_loss(self, model, inputs, return_outputs=False, num_items_in_batch=None):
                labels = inputs.get("labels")
                # Forward pass
                outputs = model(**inputs)
                logits = outputs.get("logits")
                # compute custom loss
                loss_fct = nn.CrossEntropyLoss(weight=class_weights)
                loss = loss_fct(logits.view(-1, self.model.config.num_labels), labels.view(-1))
                return (loss, outputs) if return_outputs else loss
            
        # Training arguments
        training_args = TrainingArguments(
            output_dir=output_dir,
            num_train_epochs=3,
            per_device_train_batch_size=8,
            per_device_eval_batch_size=8,
            evaluation_strategy="epoch",
            save_strategy="epoch",
            learning_rate=2e-5,
            weight_decay=0.01,
            logging_dir="./logs",
            logging_steps=10,
            load_best_model_at_end=True,
            metric_for_best_model="eval_loss",
            greater_is_better=False,
            push_to_hub=True,
            hub_model_id="Addyk24/ThreatScan"
        )

        # Initialize trainer
        trainer = CustomTrainer(
            model=self.classifier.model,
            args=training_args,
            train_dataset=train_ds,
            eval_dataset=test_ds,
            callbacks=[EarlyStoppingCallback(early_stopping_patience=1)]
        )

        # Train
        print("🔄 Starting training...")
        trainer.train()

        # Evaluate
        print("\nFinal evaluation:")
        eval_results = trainer.evaluate()
        print(f"Final metrics: {eval_results}")

        # Save Model
        trainer.save_model(output_dir)
        print(f"Model saved to {output_dir}")

        trainer.push_to_hub(commit_message="Adding Intent Classifier - debug/threat")

        return trainer
    

def model_prediction(data,model_dir = "trained_models/intent_classifier"):
    """ Predicting From Finetuned Model """

    print("🔄 Loading trained model...")
    classifier = IntentClassifier()

    try:
        classifier.load_model(fine_tuned_model_path)
        print("✅ Loaded model from Hugging Face")     
    except Exception:
        try:
            classifier.load_model(model_dir)
        except Exception as e2:
            print(f" Could not load any model: {e2}")
            return None
        
    try:
        classifier.tokenizer = AutoTokenizer.from_pretrained(model_dir, local_files_only=True)
    except Exception:
        print(" Tokenizer not found in fine-tuned folder. Using base model tokenizer.")
        try:
            classifier.tokenizer = AutoTokenizer.from_pretrained(fine_tuned_model_path, local_files_only=True)
        except Exception:
            try:
                classifier.tokenizer = AutoTokenizer.from_pretrained("distilbert/distilbert-base-uncased", local_files_only=True)
            except Exception:
                classifier.tokenizer = AutoTokenizer.from_pretrained("distilbert/distilbert-base-uncased", local_files_only=False, timeout=15)
    print(" Prediction on Wayyyy!")

    try:
        result = classifier.predict(data)
        print(f"   Predicted: {result['Problem_type']} (confidence: {result['confidence']:.3f})")
        return {
            "Problem_type": result['Problem_type'],
            "confidence": f"{result['confidence']:.3f}",
        }
    except Exception as e:
        print(f" Error predicting for text: {data}")

    
def train_intent_classifier(dataset, model_path="distilbert-base-uncased"):
    """
    Main function to train the intent classifier
    """
    trainer = IntentClassifierTrainer(dataset)
    train_ds, test_ds = trainer.prepare_dataset()
    
    # Train the model
    trained_model = trainer.train_model(train_ds, test_ds)
    
    return trained_model


# Testing function to verify model works correctly
def test_model_predictions(model_path, test_samples):
    """Test the trained model with sample inputs"""
    classifier = IntentClassifier()
    classifier.load_model()
    
    print("\n=== Model Test Results ===")
    for i, sample in enumerate(test_samples):
        result = classifier.predict(sample)
        print(f"Sample {i+1}: {sample[:100]}...")
        print(f"Prediction: {result['Problem_type']} (confidence: {result['confidence']:.4f})")
        print("-" * 50)

if __name__ == "__main__":
    print(" Initializing Intent Classifier Trainer...")
    try:
        print("\n Training completed successfully!")
        
        single_text = """Title: SQL query fails after sanitize attempt. Body: I'm trying to fix a bug. Code: <code>q = "SELECT * FROM users WHERE id = '%s'" % user_input</code> I tried input: "'; DROP TABLE users; --" and now get HTTP 500. How to fix?
        """
        test_samples = [
            "debug: connection timeout error",
            "malicious code detected in system",
            "threat: unauthorized access attempt"
        ]

        # Test the trained model
        test_model_predictions("trained_models/intent_classifier", test_samples)
    except Exception as e:
        print(f"Error during training: {e}")
        import traceback
        traceback.print_exc()
