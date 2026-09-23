import joblib
import os
import numpy as np
from src.core.event_bus import bus
from src.core.logger import system_logger, alert_logger
from src.ml.feature_extractor import FeatureExtractor

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False

class MLEngine:
    def __init__(self, model_dir="models"):
        self.model_dir = model_dir
        self.extractor = FeatureExtractor()
        
        # Load Model Assets
        self.model = self._load_asset("ids_model.joblib")
        self.scaler = self._load_asset("scaler.joblib")
        self.label_encoder = self._load_asset("label_encoder.joblib")
        
        # Initialize Explainable AI (SHAP)
        self.explainer = None
        if SHAP_AVAILABLE and self.model:
            try:
                system_logger.info("Initializing SHAP TreeExplainer (this may take a moment)...")
                self.explainer = shap.TreeExplainer(self.model)
                system_logger.info("SHAP explainer initialized successfully.")
            except Exception as e:
                system_logger.warning(f"Could not initialize SHAP explainer: {e}")
        elif not SHAP_AVAILABLE:
            system_logger.warning("SHAP library not installed. Explainable AI features disabled.")
        
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
            explanation = ""
            if self.explainer and self.model:
                try:
                    # Calculate SHAP values for the flagged flow
                    shap_vals = self.explainer.shap_values(scaled_features)
                    
                    # For Random Forest, shap_values is typically a list of arrays (one per class)
                    if isinstance(shap_vals, list):
                        # Ensure prediction_idx is an integer to index the list
                        idx = int(prediction_idx) if hasattr(prediction_idx, 'item') else prediction_idx
                        instance_shap = shap_vals[idx][0]
                    else:
                        instance_shap = shap_vals[0]
                    
                    # Extract the top 3 most influential features
                    top_indices = np.argsort(np.abs(instance_shap))[-3:][::-1]
                    top_features = [f"Feature_{i} (impact: {instance_shap[i]:.4f})" for i in top_indices]
                    explanation = f" | Top Anomalous Features: {', '.join(top_features)}"
                except Exception as e:
                    explanation = f" | [SHAP calculation failed: {e}]"

            alert_msg = f"[AI ALERT] Malicious activity detected in flow {flow.flow_id}. Type: {prediction}{explanation}"
            alert_logger.error(alert_msg)
            
            # Emit event with explanation metadata
            bus.emit("security_alert", {
                "type": "AI_DETECTION", 
                "label": prediction, 
                "flow": flow.flow_id,
                "explanation": explanation
            })

    def _heuristic_check(self, flow, features):
        # Simulated heuristic for testing purposes (e.g., abnormally high packet count)
        if features[0][1] > 1000: # packets > 1000
            return "Potential DoS Attack"
        return "BENIGN"

if __name__ == "__main__":
    engine = MLEngine()
