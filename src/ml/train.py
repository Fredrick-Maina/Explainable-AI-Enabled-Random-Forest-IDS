import pandas as pd
import numpy as np
import os
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

class IDSTrainer:
    def __init__(self, data_dir="data", model_dir="models", sample_frac=0.05, max_n_jobs=2):
        self.data_dir = data_dir
        self.model_dir = model_dir
        self.sample_frac = sample_frac
        self.max_n_jobs = max_n_jobs
        os.makedirs(self.model_dir, exist_ok=True)
        
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.model = RandomForestClassifier(
            n_estimators=100, 
            class_weight='balanced', 
            n_jobs=self.max_n_jobs, 
            random_state=42
        )

    def _stratified_sample(self, df):
        # Pass sample_frac=1.0 to train on 100% of the dataset (e.g. in Google Colab)
        if 'Label' not in df.columns or len(df) <= 1000 or self.sample_frac >= 1.0:
            return df
        indices = []
        for _, group in df.groupby('Label'):
            n = max(2, int(len(group) * self.sample_frac))
            n = min(len(group), n)
            indices.extend(group.sample(n=n, random_state=42).index)
        return df.loc[indices].copy()

    def load_and_clean_data(self, file_name=None):
        """Loads CSV files from the data directory and cleans them with memory optimization."""
        data_path = os.path.join(self.data_dir, file_name) if file_name else self.data_dir
        
        if not os.path.exists(data_path) or (os.path.isdir(data_path) and not os.listdir(data_path)):
            print(f"[!] No data found at {data_path}. Generating synthetic data for demonstration...")
            return self._generate_synthetic_data()

        print(f"[*] Loading data from {data_path} (sampling ratio: {self.sample_frac*100}% per file)...")
        dfs = []
        if os.path.isdir(data_path):
            all_files = []
            for root, _, files in os.walk(data_path):
                for f in files:
                    if f.endswith('.csv'):
                        all_files.append(os.path.join(root, f))
            
            for f in all_files:
                print(f"  -> Reading {os.path.basename(f)}...")
                chunk_df = pd.read_csv(f)
                chunk_df.columns = chunk_df.columns.str.strip()
                chunk_df = self._stratified_sample(chunk_df)
                dfs.append(chunk_df)
            df = pd.concat(dfs, ignore_index=True)
        else:
            df = pd.read_csv(data_path)
            df.columns = df.columns.str.strip()
            df = self._stratified_sample(df)

        # 1. Handle Inf and NaN
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)

        # 2. Drop non-predictive columns (Specific to CIC-IDS2017)
        drop_cols = ['Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Timestamp']
        df.drop(columns=[c for c in drop_cols if c in df.columns], inplace=True)

        # 3. Filter out ultra-rare classes with < 2 samples to allow stratified train/test split
        label_counts = df['Label'].value_counts()
        rare_labels = label_counts[label_counts < 2].index
        if len(rare_labels) > 0:
            print(f"[*] Filtering out rare classes with < 2 instances: {list(rare_labels)}")
            df = df[~df['Label'].isin(rare_labels)].copy()

        # 4. Downcast float64 to float32 to cut RAM in half
        float_cols = df.select_dtypes(include=['float64']).columns
        df[float_cols] = df[float_cols].astype(np.float32)

        print(f"[*] Loaded dataset with total {len(df)} cleaned rows.")
        return df

    def _generate_synthetic_data(self):
        """Creates a dummy dataset for testing the pipeline."""
        n_samples = 1000
        n_features = 78
        X = np.random.rand(n_samples, n_features).astype(np.float32)
        y = np.random.choice(['BENIGN', 'DDoS'], n_samples)
        
        columns = [f"Feature_{i}" for i in range(n_features)]
        df = pd.DataFrame(X, columns=columns)
        df['Label'] = y
        return df

    def train(self, df):
        print("[*] Preprocessing data for training...")
        X = df.drop(columns=['Label'])
        y = df['Label']

        # Encode labels
        y_encoded = self.label_encoder.fit_transform(y)
        
        # Split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
        )

        # Scale
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        print(f"[*] Training Random Forest model (n_jobs={self.max_n_jobs}) on {len(X_train)} samples...")
        self.model.fit(X_train_scaled, y_train)

        # Evaluate
        y_pred = self.model.predict(X_test_scaled)
        print("\n--- Training Results ---")
        print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
        
        unique_labels = np.unique(np.concatenate([y_test, y_pred]))
        target_names = [str(name) for name in self.label_encoder.inverse_transform(unique_labels)]
        print(classification_report(y_test, y_pred, labels=unique_labels, target_names=target_names))

        self.save_assets()

    def save_assets(self):
        print(f"[*] Saving model assets to {self.model_dir}...")
        joblib.dump(self.model, os.path.join(self.model_dir, "ids_model.joblib"))
        joblib.dump(self.scaler, os.path.join(self.model_dir, "scaler.joblib"))
        joblib.dump(self.label_encoder, os.path.join(self.model_dir, "label_encoder.joblib"))
        print("[+] Training complete.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Train IDS Random Forest Model")
    parser.add_argument("--sample_frac", type=float, default=0.05, help="Sampling fraction per CSV (e.g. 0.05 for 5%, 1.0 for 100% full dataset training)")
    parser.add_argument("--n_jobs", type=int, default=2, help="Number of CPU threads for training")
    args = parser.parse_args()

    trainer = IDSTrainer(sample_frac=args.sample_frac, max_n_jobs=args.n_jobs)
    data = trainer.load_and_clean_data()
    trainer.train(data)
