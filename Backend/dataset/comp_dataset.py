import pandas as pd
import random
import itertools
from datetime import datetime, timedelta
import uuid
import string

class LargeSyntheticDatasetGenerator:
    """
    Generate 100K+ high-quality synthetic examples for threat vs debug classification
    """
    
    def __init__(self):
        # Base templates for generating variations
        self.threat_templates = {
            'malware': [
                "{malware_type} detected in {location} {action}",
                "{severity} malware infection found {details}",
                "Security alert: {malware_type} {action} on {system}",
                "{malware_type} signature match identified {location}",
                "Malicious {file_type} containing {malware_type} {action}",
            ],
            'network_attack': [
                "{attack_type} detected from {source} {action}",
                "Network intrusion: {attack_type} attempting {target}",
                "Suspicious {protocol} traffic indicating {attack_type}",
                "{attack_type} blocked by {security_system}",
                "Multiple {attack_type} attempts from {source}",
            ],
            'access_violation': [
                "Unauthorized {access_type} attempt {details}",
                "{privilege} escalation detected in {location}",
                "Access denied: {user_type} attempting {action}",
                "Authentication failure: {failure_reason} {details}",
                "Suspicious login activity: {login_details}",
            ],
            'data_security': [
                "{data_type} exposure detected in {location}",
                "Data breach attempt: {attack_method} {details}",
                "Sensitive information leakage via {vector}",
                "Unauthorized data access in {system} {details}",
                "{data_type} harvesting attempt detected",
            ],
            'web_attack': [
                "{web_attack} detected in {application} {details}",
                "Web vulnerability exploit: {exploit_type} {action}",
                "{injection_type} injection attempt in {target}",
                "Cross-site attack detected: {attack_details}",
                "Web application compromise via {method}",
            ]
        }
        
        self.debug_templates = {
            'code_error': [
                "{exception_type} thrown in {location} {details}",
                "{error_type} error encountered in {component}",
                "Runtime exception: {exception_details} {location}",
                "{language} compilation error: {error_details}",
                "Code execution failure: {failure_reason}",
            ],
            'database_issue': [
                "Database {operation} failed: {error_reason}",
                "{db_type} connection {issue} {details}",
                "SQL query performance issue: {performance_problem}",
                "Database transaction {transaction_issue} {details}",
                "{db_component} error: {error_description}",
            ],
            'network_issue': [
                "{protocol} connection {issue} {details}",
                "Network {problem_type} causing {symptom}",
                "{service} service {status} {reason}",
                "API endpoint {endpoint_issue} {details}",
                "Load balancer {lb_issue} affecting {service}",
            ],
            'performance_issue': [
                "{resource_type} utilization {threshold} {details}",
                "Performance degradation: {performance_issue}",
                "{component} response time {time_issue} {details}",
                "Memory management issue: {memory_problem}",
                "{system_component} bottleneck detected {details}",
            ],
            'config_issue': [
                "Configuration {config_issue} in {component}",
                "{service} startup failure: {startup_issue}",
                "Environment variable {env_issue} {details}",
                "Deployment issue: {deployment_problem}",
                "{system} misconfiguration causing {symptom}",
            ]
        }
        
        # Vocabulary pools for generating variations
        self.vocab = {
            # Threat vocabulary
            'malware_type': ['virus', 'trojan', 'worm', 'ransomware', 'spyware', 'adware', 'rootkit', 'botnet'],
            'attack_type': ['brute force', 'DDoS', 'man-in-the-middle', 'port scan', 'packet sniffing', 'ARP spoofing'],
            'web_attack': ['SQL injection', 'XSS attack', 'CSRF attack', 'path traversal', 'buffer overflow'],
            'injection_type': ['SQL', 'NoSQL', 'LDAP', 'XPath', 'OS command', 'script'],
            'exploit_type': ['zero-day', 'buffer overflow', 'privilege escalation', 'code injection'],
            'access_type': ['file access', 'database access', 'system access', 'network access', 'admin access'],
            'data_type': ['personal data', 'credit card info', 'authentication tokens', 'session data', 'user credentials'],
            'security_system': ['firewall', 'IDS', 'antivirus', 'endpoint protection', 'SIEM'],
            
            # Debug vocabulary  
            'exception_type': ['NullPointerException', 'IndexOutOfBoundsException', 'ClassNotFoundException', 
                             'IllegalArgumentException', 'ConcurrentModificationException', 'StackOverflowError'],
            'error_type': ['syntax', 'runtime', 'logic', 'compilation', 'linking', 'configuration'],
            'db_type': ['MySQL', 'PostgreSQL', 'MongoDB', 'Redis', 'Oracle', 'SQL Server'],
            'protocol': ['HTTP', 'HTTPS', 'TCP', 'UDP', 'WebSocket', 'gRPC', 'REST', 'SOAP'],
            'language': ['Python', 'Java', 'JavaScript', 'C++', 'C#', 'Go', 'Rust', 'PHP'],
            'resource_type': ['CPU', 'memory', 'disk', 'network', 'thread pool', 'connection pool'],
            
            # Common elements
            'location': ['system memory', 'application server', 'database server', 'web server', 'file system'],
            'component': ['authentication module', 'payment processor', 'user interface', 'API gateway', 'message queue'],
            'system': ['production server', 'staging environment', 'development system', 'backup server'],
            'severity': ['critical', 'high-priority', 'urgent', 'severe', 'major'],
            'source': ['external IP', 'unknown host', 'suspicious domain', 'compromised account'],
        }
        
        # Add more specific vocabulary
        self.generate_extended_vocab()
    
    def generate_extended_vocab(self):
        """Generate additional vocabulary variations"""
        
        # Generate IP addresses
        self.vocab['ip_addresses'] = [f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}" 
                                     for _ in range(100)]
        
        # Generate file types
        self.vocab['file_type'] = ['executable', 'script', 'document', 'archive', 'image', 'configuration file']
        
        # Generate error codes
        self.vocab['error_codes'] = [f"ERROR_{random.randint(1000,9999)}" for _ in range(50)]
        
        # Generate timestamps
        base_time = datetime.now()
        self.vocab['timestamps'] = [(base_time - timedelta(days=random.randint(1,30))).strftime("%Y-%m-%d %H:%M:%S") 
                                   for _ in range(100)]
        
        # Generate user agents, domains, ports
        self.vocab['ports'] = [str(p) for p in [80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 3389, 5432, 3306]]
        self.vocab['domains'] = [f"suspicious-{random.choice(string.ascii_lowercase)}{random.randint(100,999)}.com" 
                                for _ in range(50)]
    
    def generate_threat_examples(self, n_examples):
        """Generate threat examples using templates and vocabulary"""
        threats = []
        
        for _ in range(n_examples):
            # Choose random category and template
            category = random.choice(list(self.threat_templates.keys()))
            template = random.choice(self.threat_templates[category])
            
            # Fill template with vocabulary
            example = self.fill_template(template, is_threat=True)
            
            # Add variations
            example = self.add_variations(example, is_threat=True)
            
            threats.append({
                'problem': example,
                'label': 'threat',
                'category': category,
                'length_category': self.get_length_category(example)
            })
        
        return threats
    
    def generate_debug_examples(self, n_examples):
        """Generate debug examples using templates and vocabulary"""
        debugs = []
        
        for _ in range(n_examples):
            # Choose random category and template
            category = random.choice(list(self.debug_templates.keys()))
            template = random.choice(self.debug_templates[category])
            
            # Fill template with vocabulary
            example = self.fill_template(template, is_threat=False)
            
            # Add variations
            example = self.add_variations(example, is_threat=False)
            
            debugs.append({
                'problem': example,
                'label': 'debug',
                'category': category,
                'length_category': self.get_length_category(example)
            })
        
        return debugs
    
    def fill_template(self, template, is_threat=True):
        """Fill template placeholders with vocabulary"""
        
        # Extract placeholders from template
        import re
        placeholders = re.findall(r'\{([^}]+)\}', template)
        
        filled = template
        for placeholder in placeholders:
            if placeholder in self.vocab:
                value = random.choice(self.vocab[placeholder])
                filled = filled.replace(f"{{{placeholder}}}", value)
            else:
                # Generate generic replacement
                filled = filled.replace(f"{{{placeholder}}}", self.generate_generic_text(placeholder))
        
        return filled
    
    def generate_generic_text(self, placeholder_type):
        """Generate generic text for unknown placeholders"""
        generic_map = {
            'action': random.choice(['detected', 'blocked', 'identified', 'found', 'discovered']),
            'details': random.choice(['in production system', 'during routine scan', 'by security monitoring', 'in log analysis']),
            'target': random.choice(['user database', 'web application', 'file server', 'network infrastructure']),
            'method': random.choice(['automated script', 'manual exploitation', 'social engineering', 'phishing campaign']),
            'issue': random.choice(['timeout', 'failure', 'interruption', 'corruption', 'unavailability']),
            'reason': random.choice(['configuration error', 'resource exhaustion', 'network congestion', 'hardware failure']),
        }
        
        return generic_map.get(placeholder_type, f"unknown_{placeholder_type}")
    
    def add_variations(self, example, is_threat=True):
        """Add variations to make examples more diverse"""
        
        variations = []
        
        # Add prefixes occasionally
        if random.random() < 0.3:
            if is_threat:
                prefixes = ['Security Alert:', 'THREAT DETECTED:', 'WARNING:', 'CRITICAL:']
            else:
                prefixes = ['ERROR:', 'DEBUG:', 'SYSTEM:', 'APPLICATION:']
            example = f"{random.choice(prefixes)} {example}"
        
        # Add timestamps occasionally
        if random.random() < 0.2:
            timestamp = random.choice(self.vocab['timestamps'])
            example = f"[{timestamp}] {example}"
        
        # Add severity occasionally
        if random.random() < 0.25:
            if is_threat:
                severities = ['High severity', 'Critical priority', 'Urgent attention required']
            else:
                severities = ['Low priority', 'Development issue', 'Non-critical']
            example = f"{example} - {random.choice(severities)}"
        
        # Randomly adjust capitalization
        if random.random() < 0.1:
            example = example.upper()
        elif random.random() < 0.1:
            example = example.lower()
        
        return example
    
    def get_length_category(self, text):
        """Categorize text by length"""
        word_count = len(text.split())
        if word_count < 10:
            return 'short'
        elif word_count < 25:
            return 'medium'  
        else:
            return 'long'
    
    def generate_dataset(self, total_size=100000, balance_ratio=0.5):
        """Generate large balanced dataset"""
        
        n_threats = int(total_size * balance_ratio)
        n_debugs = total_size - n_threats
        
        print(f"Generating {total_size} examples...")
        print(f"Threats: {n_threats}, Debug: {n_debugs}")
        
        # Generate examples
        threats = self.generate_threat_examples(n_threats)
        debugs = self.generate_debug_examples(n_debugs)
        
        # Combine and shuffle
        dataset = threats + debugs
        random.shuffle(dataset)
        
        return dataset
    
    def save_to_csv(self, dataset, filename='large_synthetic_dataset.csv'):
        """Save dataset to CSV with analysis"""
        
        df = pd.DataFrame(dataset)
        
        # Add text statistics
        df['word_count'] = df['problem'].apply(lambda x: len(x.split()))
        df['char_count'] = df['problem'].apply(len)
        
        # Save main dataset
        main_df = df[['problem', 'label']].copy()
        main_df.to_csv(filename, index=False)
        
        # Save detailed version with metadata
        detailed_filename = filename.replace('.csv', '_detailed.csv')
        df.to_csv(detailed_filename, index=False)
        
        # Print analysis
        self.analyze_dataset(df)
        
        print(f"\n✅ Dataset saved!")
        print(f"📁 Main dataset: {filename}")
        print(f"📁 Detailed dataset: {detailed_filename}")
        
        return df
    
    def analyze_dataset(self, df):
        """Analyze the generated dataset"""
        
        print("\n" + "="*50)
        print("DATASET ANALYSIS")
        print("="*50)
        
        # Basic statistics
        print(f"Total examples: {len(df):,}")
        print(f"\nLabel distribution:")
        label_counts = df['label'].value_counts()
        for label, count in label_counts.items():
            percentage = (count / len(df)) * 100
            print(f"  {label}: {count:,} ({percentage:.1f}%)")
        
        # Length analysis
        print(f"\nText length analysis:")
        length_stats = df.groupby('label')['word_count'].agg(['mean', 'std', 'min', 'max'])
        print(length_stats.round(2))
        
        # Category distribution
        print(f"\nCategory distribution:")
        category_counts = df.groupby(['label', 'category']).size().unstack(fill_value=0)
        print(category_counts)
        
        # Length category balance
        print(f"\nLength category balance:")
        length_balance = pd.crosstab(df['label'], df['length_category'])
        print(length_balance)
        
        # Sample examples
        print(f"\n" + "="*30)
        print("SAMPLE EXAMPLES")
        print("="*30)
        
        print("\nSample threats:")
        threat_samples = df[df['label'] == 'threat']['problem'].sample(5)
        for i, sample in enumerate(threat_samples, 1):
            print(f"{i}. {sample}")
        
        print(f"\nSample debug examples:")
        debug_samples = df[df['label'] == 'debug']['problem'].sample(5)
        for i, sample in enumerate(debug_samples, 1):
            print(f"{i}. {sample}")

def generate_large_dataset():
    """Main function to generate 100K+ dataset"""
    
    print("🚀 Starting large-scale synthetic dataset generation...")
    
    generator = LargeSyntheticDatasetGenerator()
    
    # Generate 100K examples (you can increase this)
    dataset = generator.generate_dataset(total_size=100000, balance_ratio=0.5)
    
    # Save to CSV
    df = generator.save_to_csv(dataset, 'threat_debug_100k.csv')
    
    print("\n🎉 Dataset generation complete!")
    return df

# Additional utility functions for different dataset sizes
def generate_custom_size(size, filename=None):
    """Generate dataset of custom size"""
    
    if filename is None:
        filename = f'threat_debug_{size//1000}k.csv'
    
    print(f"Generating {size:,} examples...")
    
    generator = LargeSyntheticDatasetGenerator()
    dataset = generator.generate_dataset(total_size=size, balance_ratio=0.5)
    df = generator.save_to_csv(dataset, filename)
    
    return df

def generate_multiple_sizes():
    """Generate datasets of different sizes for experimentation"""
    
    sizes = [10000, 25000, 50000, 100000, 200000]
    
    for size in sizes:
        print(f"\n{'='*60}")
        print(f"GENERATING {size:,} EXAMPLES")
        print(f"{'='*60}")
        
        filename = f'threat_debug_{size//1000}k.csv'
        generate_custom_size(size, filename)

if __name__ == "__main__":
    # Generate 100K dataset
    df = generate_large_dataset()
    
    # Uncomment below to generate multiple sizes
    # generate_multiple_sizes()
    
    print("\n🔥 Ready for training!")
    print("Usage in your code:")
    print("df = pd.read_csv('threat_debug_100k.csv')")
    print("# Convert to your dataset format and train")


class WeightedLossTrainer(Trainer):
"""Custom trainer with weighted loss for class imbalance"""

def __init__(self, class_weights=None, *args, **kwargs):
    super().__init__(*args, **kwargs)
    self.class_weights = class_weights
    
def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
    """Compute loss with class weights - accepts any additional kwargs"""
    labels = inputs.get("labels")
    outputs = model(**inputs)
    
    if labels is not None and self.class_weights is not None:
        logits = outputs.get("logits")
        loss_fct = nn.CrossEntropyLoss(weight=self.class_weights.to(labels.device))
        loss = loss_fct(logits.view(-1, self.model.config.num_labels), labels.view(-1))
    else:
        loss = outputs["loss"] if isinstance(outputs, dict) else outputs.loss
        
    return (loss, outputs) if return_outputs else loss

        # Calculate class weights
        class_weights = self.calculate_class_weights(train_ds)

        trainer = WeightedLossTrainer(
            class_weights=class_weights,  # This is the key fix!
            model=model,
            args=training_args,
            train_dataset=train_ds,
            eval_dataset=test_ds,
            compute_metrics=self.compute_metrics,
            callbacks=[EarlyStoppingCallback(early_stopping_patience=3)]
        )