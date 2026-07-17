import joblib
import os
import numpy as np
from src.core.event_bus import bus
from src.core.logger import system_logger, alert_logger
from src.ml.feature_extractor import FeatureExtractor

class MLEngine:
    def __init__(self, model_dir="models"):
        self.model_dir = model_dir
        self.extractor = FeatureExtractor()
        
        # Load Model Assets
        self.model = self._load_asset("ids_model.joblib")
        self.scaler = self._load_asset("scaler.joblib")
        self.label_encoder = self._load_asset("label_encoder.joblib")
        
        # Subscribe to flow events for analysis
        bus.subscribe("analyze_flow", self.analyze)

    def _load_asset(self, filename):
        path = os.path.join(self.model_dir, filename)
        if os.path.exists(path):
            system_logger.info(f"Loading AI asset: {filename}")
            return joblib.load(path)
        else:
            system_logger.warning(f"AI asset {filename} not found in {self.model_dir}")
            return None

    def analyze(self, flow):
        system_logger.debug(f"AI Engine analyzing flow: {flow.flow_id}")
        
        # 1. Extract Features
        features = self.extractor.extract(flow)
        if features is None:
            return

        # 2. Run Inference
        if self.model and self.scaler:
            # Scale features before prediction
            scaled_features = self.scaler.transform(features)
            prediction_idx = self.model.predict(scaled_features)[0]
            
            # Convert index back to label if possible
            if self.label_encoder:
                prediction = self.label_encoder.inverse_transform([prediction_idx])[0]
            else:
                prediction = f"Class_{prediction_idx}"
        else:
            # Simple heuristic simulation for prototype testing
            prediction = self._heuristic_check(flow, features)

        # 3. Handle Results
        if prediction != "BENIGN":
            alert_msg = f"[AI ALERT] Malicious activity detected in flow {flow.flow_id}. Type: {prediction}"
            alert_logger.error(alert_msg)
            bus.emit("security_alert", {"type": "AI_DETECTION", "label": prediction, "flow": flow.flow_id})

    def _heuristic_check(self, flow, features):
        # Simulated heuristic for testing purposes (e.g., abnormally high packet count)
        if features[0][1] > 1000: # packets > 1000
            return "Potential DoS Attack"
        return "BENIGN"

if __name__ == "__main__":
    engine = MLEngine()
