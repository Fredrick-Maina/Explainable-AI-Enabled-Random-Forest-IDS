import pandas as pd
import numpy as np
import os
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

class IDSTrainer:
    def __init__(self, data_dir="data", model_dir="models"):
        self.data_dir = data_dir
        self.model_dir = model_dir
        os.makedirs(self.model_dir, exist_ok=True)
        
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.model = RandomForestClassifier(n_estimators=100, class_weight='balanced', n_jobs=-1, random_state=42)

    def load_and_clean_data(self, file_name=None):
        """Loads CSV files from the data directory and cleans them."""
        data_path = os.path.join(self.data_dir, file_name) if file_name else self.data_dir
        
        if not os.path.exists(data_path) or (os.path.isdir(data_path) and not os.listdir(data_path)):
            print(f"[!] No data found at {data_path}. Generating synthetic data for demonstration...")
            return self._generate_synthetic_data()

        print(f"[*] Loading data from {data_path}...")
        # If directory, load all CSVs
        if os.path.isdir(data_path):
            all_files = [os.path.join(data_path, f) for f in os.listdir(data_path) if f.endswith('.csv')]
            df = pd.concat((pd.read_csv(f) for f in all_files), ignore_index=True)
        else:
            df = pd.read_csv(data_path)

        # 1. Clean column names
        df.columns = df.columns.str.strip()

        # 2. Handle Inf and NaN
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)

        # 3. Drop non-predictive columns (Specific to CIC-IDS2017)
        drop_cols = ['Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Timestamp']
        df.drop(columns=[c for c in drop_cols if c in df.columns], inplace=True)

        return df

    def _generate_synthetic_data(self):
        """Creates a dummy dataset for testing the pipeline."""
        n_samples = 1000
        n_features = 78
        X = np.random.rand(n_samples, n_features)
        # Create 2 classes: BENIGN and ATTACK
        y = np.random.choice(['BENIGN', 'DDoS'], n_samples)
        
        columns = [f"Feature_{i}" for i in range(n_features)]
        df = pd.DataFrame(X, columns=columns)
        df['Label'] = y
        return df

    def train(self, df):
        print("[*] Preprocessing data...")
        X = df.drop(columns=['Label'])
        y = df['Label']

        # Encode labels
        y_encoded = self.label_encoder.fit_transform(y)
        
        # Split
        X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded)

        # Scale
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        print(f"[*] Training Random Forest model on {len(X_train)} samples...")
        self.model.fit(X_train_scaled, y_train)

        # Evaluate
        y_pred = self.model.predict(X_test_scaled)
        print("\n--- Training Results ---")
        print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
        print(classification_report(y_test, y_pred, target_names=self.label_encoder.classes_))

        self.save_assets()

    def save_assets(self):
        print(f"[*] Saving model assets to {self.model_dir}...")
        joblib.dump(self.model, os.path.join(self.model_dir, "ids_model.joblib"))
        joblib.dump(self.scaler, os.path.join(self.model_dir, "scaler.joblib"))
        joblib.dump(self.label_encoder, os.path.join(self.model_dir, "label_encoder.joblib"))
        print("[+] Training complete.")

if __name__ == "__main__":
    trainer = IDSTrainer()
    data = trainer.load_and_clean_data()
    trainer.train(data)
