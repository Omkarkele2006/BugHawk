import torch
import torch.nn as nn
from transformers import AutoModelForSequenceClassification, AutoTokenizer,EarlyStoppingCallback

from transformers import Trainer, TrainingArguments
from sklearn.metrics import accuracy_score,f1_score,classification_report
from sklearn.utils.class_weight import compute_class_weight
from torch.utils.data import Dataset
from typing import Dict , Optional
from datasets import load_dataset,ClassLabel


import os
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split


ds = load_dataset("Addyk24/code_threat_maintance")

model_path = "distilbert/distilbert-base-uncased"

fine_tuned_model_path = "Addyk24/ThreatScan"




class IntentClassifier:
    def __init__(self):
        self.model_path = fine_tuned_model_path
        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.model = None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.label_mapping = {
            "debug" : 0,
            "threat" : 1
        }

        # Create reverse mapping (integer to string) for predictions
        self.id2label = {v: k for k, v in self.label_mapping.items()}

    def load_model(self, model_path = fine_tuned_model_path):
        """ Loading of Finetuned Model """
        path_to_use = model_path if model_path else self.model_path

        self.model = AutoModelForSequenceClassification.from_pretrained(path_to_use)

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
            # Check if list of dicts or list of strings
            if all(isinstance(t, dict) and "problem" in t for t in text):
                texts = [t["problem"] for t in text]
            elif all(isinstance(t, str) for t in text):
                texts = text
            else:
                raise ValueError("List must contain all strings or all dicts with 'problem' key")
        elif isinstance(text, str):
            texts = [text]
        else:
            raise ValueError("Unsupported input type")

        tokenized_text = self.tokenizer(
            texts,
            truncation = True,
            padding = True,
            max_length = max_length,
            return_tensors = "pt"
        )

        return tokenized_text
    
    def predict(self,text):
        """ Predicting Value From Finetuned Model """
        if self.model is None:
            raise ValueError("Model not loaded")
        tokenized_text = self.process_text(text)

        device = next(self.model.parameters()).device
        tokenized_text = {k: v.to(device) for k, v in tokenized_text.items()}

        with torch.no_grad():
            outputs = self.model(**tokenized_text)
            predicted_value = torch.nn.functional.softmax(outputs.logits,dim=-1)

        prediction_class = torch.argmax(predicted_value,dim=-1).item()
        confidence = predicted_value[0][prediction_class].item()

        return {
            "Problem_type" : self.id2label[prediction_class],
            "confidence" : float(confidence) 
        }
    

class IntentClassifierTrainer:
    def __init__(self):
        self.classifier = IntentClassifier()
        self.ds = ds
        
    def encode_labels(self,datapoint):
        datapoint["labels"] = int(self.classifier.label_mapping[datapoint["label"]])
        return datapoint
    

    def normalize_data(Self,datapoint):
        datapoint["label"] = datapoint["label"].lower()
        return datapoint

    def prepare_dataset(self):
        """ Prepare dataset for training proper label mapping """


        # ds["data"]= ds["data"].map(self.normalize_data)
        # ds_clean = ds["data"].map(self.encode_labels)

        # ds_clean["data"]["label"] = ds_clean["data"]['label'].map(self.classifier.label_mapping)
        # label_names = list(self.classifier.label_mapping.keys())

        # ds_clean = ds_clean.cast_column(
        #     "labels",
        #     ClassLabel(names=label_names)
        # )

        dataset = ds.train_test_split(
            test_size = 0.2,
            stratify_by_column="labels",
            seed=0
        )

        train_ds = dataset["train"]
        test_ds = dataset["test"]
        # print(ds_clean["train"].features)
        train_ds = train_ds.map(self.classifier.process_text,batched=True,remove_columns=["problem"])
        test_ds = test_ds.map(self.classifier.process_text,batched=True,remove_columns=["problem"])
        


        return train_ds,test_ds

    def compute_metrics(self, eval_pred):

        """Compute metrics for evaluation"""

        predictions, labels = eval_pred
        predictions = np.argmax(predictions, axis=1)
        
        accuracy = accuracy_score(labels, predictions)
        f1 = f1_score(labels, predictions, average='weighted')
        f1_macro = f1_score(labels,predictions,average="macro")
        
        # Print detailed classification report
        print("\nClassification Report:")
        print(classification_report(labels, predictions, target_names=list(self.classifier.id2label.values())))

        # Return with proper eval_ prefix
        return {
            'eval_accuracy': accuracy,  
            'eval_f1': f1,
            'f1_macro': f1_macro       
        }

    def calculate_class_weights(self, train_ds):
        """Calculate class weights for imbalanced dataset"""
        labels = np.array(train_ds['labels'])
        classes = np.unique(labels)
        
        class_weights = compute_class_weight(
            'balanced',
            classes=classes,
            y=labels
        )
        
        print(f"Class distribution: {np.bincount(labels)}")
        print(f"Class weights: {dict(zip(classes, class_weights))}")
        
        return torch.tensor(class_weights, dtype=torch.float32)
    


    def train_model(self,train_ds,test_ds,output_dir="trained_models/intent_classifier"):
        """ Model Training With Dataset """
        


        model = AutoModelForSequenceClassification.from_pretrained(
            self.classifier.model_path,
            num_labels = len(self.classifier.label_mapping),
            id2label = self.classifier.id2label,
            label2id = self.classifier.label_mapping,
            )
        
        # Reinitialize classifier head to avoid bad initialization
        if hasattr(model, 'classifier'):
            model.classifier.weight.data.normal_(mean=0.0, std=0.02)
            model.classifier.bias.data.zero_()


        training_args = TrainingArguments(
            output_dir=output_dir,
            # EPOCHS AND LEARNINGS
            num_train_epochs=3,
            learning_rate=2e-5,
            warmup_steps=1000,
            weight_decay=0.01,
            # BATCH SIZES
            per_device_train_batch_size=32,
            per_device_eval_batch_size=64,
            # EVALUATION STRATEGY
            eval_strategy="steps",
            eval_steps=1000,
            save_strategy="steps",
            save_steps=1000,
            save_total_limit=3,              # Keep only best 3 checkpoints
            # LOGGINGS
            logging_dir=f"{output_dir}/logs",
            logging_steps=100,
            logging_first_step = True,

            load_best_model_at_end=True,
            metric_for_best_model="f1",
            greater_is_better=True,
            report_to="none",  # Disable wandb
            remove_unused_columns=True, # Memory optimization
            push_to_hub=False,  

            # PERFORMANCE OPTIMIZATIONS
            dataloader_num_workers=4,        # Parallel data loading
            dataloader_pin_memory=True,      # GPU optimization
            fp16=True,           # Mixed precision for faster training
            # REPRODUCIBILITY
            seed=42,
            data_seed=42,
        )

        trainer = Trainer(
            model = model,
            args=training_args,
            train_dataset=train_ds,
            eval_dataset=test_ds,
            compute_metrics=self.compute_metrics,
            callbacks=[EarlyStoppingCallback(early_stopping_patience=3)]
        )


        # Training
        print("Starting training...")
        trainer.train()

        # Evaluate final model
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
        classifier.tokenizer = AutoTokenizer.from_pretrained(model_dir)
    except Exception:
        print(" Tokenizer not found in fine-tuned folder. Using base model tokenizer.")
        try:
            classifier.tokenizer = AutoTokenizer.from_pretrained(fine_tuned_model_path)
        except Exception:
            classifier.tokenizer = AutoTokenizer.from_pretrained("distilbert/distilbert-base-uncased")
    print(" Prediction on Wayyyy!")

    try:
        result = classifier.predict(data)
        print(f"   Predicted: {result['Problem_type']} (confidence: {result['confidence']:.3f})")
        return {
            "Problem_type": result['Problem_type'],
            "confidence": f"{result['confidence']:.3f}",
            # "all_probabilities": result['all_probabilities']
        }
    except Exception as e:
        print(f" Error predicting for text: {data}")

    

def train_intent_classifier(dataset, model_path="distilbert-base-uncased"):
    """
    Main function to train the intent classifier
    """
    trainer = IntentClassifierTrainer(model_path)
    train_ds, test_ds = trainer.prepare_dataset(dataset)
    
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
        # trained_model = train_intent_classifier(ds)
        # Train the model
        # trainer = IntentClassifierTrainer()
        # train_ds, test_ds = trainer.prepare_dataset()
        # trained_model = trainer.train_model(train_ds, test_ds)
        
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
        # model_prediction(single_text)


        
    except Exception as e:
        print(f"Error during training: {e}")
        import traceback
        traceback.print_exc()

            





