"""ML pipeline management and orchestration."""
from typing import Dict, Any, List, Optional
import os
from datetime import datetime
from contextlib import nullcontext
import pandas as pd
import numpy as np

try:
    import mlflow  # type: ignore
    from mlflow.tracking import MlflowClient  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    mlflow = None

    class MlflowClient:  # type: ignore
        """Fallback MlflowClient stub when mlflow is unavailable."""

        def __init__(self, *args, **kwargs) -> None:  # noqa: D401
            pass

        def __getattr__(self, item):  # noqa: D401
            raise AttributeError(item)
from ..features.feature_engineering import FeatureEngineer
from ..models.ensemble import EnsembleModel

class MLPipeline:
    """ML pipeline for vulnerability risk scoring."""

    def __init__(self, model_dir: str = "ml_models/risk_scoring"):
        self.model_dir = model_dir
        self.feature_engineer = FeatureEngineer()
        self.model = None
        self.mlflow_client = MlflowClient() if mlflow is not None else None
        
        # Ensure model directory exists
        os.makedirs(model_dir, exist_ok=True)
        
        # Initialize MLflow
        if mlflow is not None:
            mlflow.set_tracking_uri(os.path.join(model_dir, "mlruns"))

    def train_pipeline(
        self, 
        training_data: List[Dict[str, Any]],
        labels: List[float],
        experiment_name: str = "risk_scoring"
    ) -> None:
        """Train the full ML pipeline."""
        # Start MLflow experiment
        if mlflow is not None:
            mlflow.set_experiment(experiment_name)
            run_context = mlflow.start_run()
        else:
            run_context = nullcontext()

        with run_context as run:
            # Extract features
            X = []
            for vuln in training_data:
                features = self.feature_engineer.extract_base_features(vuln)
                X.append(features)
            
            # Convert to DataFrame
            X_df = pd.DataFrame(X)
            y = np.array(labels)
            
            # Feature selection
            selected_features = self.feature_engineer.select_features(X_df, pd.Series(labels))
            
            # Transform features
            X_transformed = [
                self.feature_engineer.transform_features(record)
                for record in X_df.to_dict('records')
            ]
            
            # Initialize and train model
            self.model = EnsembleModel()
            
            # Log parameters
            if mlflow is not None:
                mlflow.log_params({
                    "n_features": len(selected_features),
                    "selected_features": ", ".join(selected_features),
                    "model_type": "stacked_ensemble"
                })
            
            # Optimize hyperparameters
            best_params = self.model.optimize_hyperparameters(X_transformed, y)
            if mlflow is not None:
                mlflow.log_params({"best_" + k: v for k, v in best_params.items()})
            
            # Train model
            self.model.fit(X_transformed, y)
            
            # Log metrics
            metrics = self.model.model_metrics
            if mlflow is not None:
                mlflow.log_metrics(metrics)
            
            # Save model
            run_id = getattr(getattr(run, "info", None), "run_id", datetime.utcnow().strftime("%Y%m%d%H%M%S"))
            model_path = os.path.join(self.model_dir, f"model_{run_id}.joblib")
            self.model.save_model(model_path)
            if mlflow is not None:
                mlflow.log_artifact(model_path)

    def predict(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Generate predictions for a vulnerability."""
        if self.model is None:
            raise RuntimeError("Model not trained or loaded")
        
        # Extract features
        features = self.feature_engineer.extract_base_features(vulnerability)
        X = self.feature_engineer.transform_features(features)
        
        # Generate prediction and confidence
        mean_pred, std_pred = self.model.predict_proba(X)
        
        # Generate SHAP explanations
        explanations = self.model.explain_prediction(X)
        
        # Format response
        return {
            "risk_score": float(mean_pred[0]),
            "confidence": 1.0 - min(1.0, float(std_pred[0])),
            "uncertainty": float(std_pred[0]),
            "feature_importance": self._format_feature_importance(explanations),
            "prediction_time": datetime.utcnow().isoformat()
        }

    def _format_feature_importance(self, explanations: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Format feature importance for API response."""
        feature_names = self.feature_engineer.get_feature_names()
        shap_values = explanations['shap_values']
        
        importance = []
        for idx, feature in enumerate(feature_names):
            importance.append({
                "feature": feature,
                "importance": float(abs(shap_values[0][idx])),
                "effect": "positive" if shap_values[0][idx] > 0 else "negative"
            })
        
        return sorted(importance, key=lambda x: x['importance'], reverse=True)

    def monitor_performance(self) -> Dict[str, Any]:
        """Monitor model performance metrics."""
        latest_metrics = self.model.model_metrics if self.model else {}
        training_history = self.model.training_history if self.model else []
        
        return {
            "current_performance": latest_metrics,
            "training_history": training_history,
            "last_update": datetime.utcnow().isoformat()
        }

    def check_model_drift(self, recent_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Check for model drift using recent predictions."""
        if not recent_data:
            return {"drift_detected": False}
        
        # Extract features from recent data
        X = []
        for vuln in recent_data:
            features = self.feature_engineer.extract_base_features(vuln)
            X.append(features)
        
        X_df = pd.DataFrame(X)
        X_transformed = self.feature_engineer.transform_features(X_df.to_dict('records')[0])
        
        # Generate predictions
        predictions = self.model.predict(X_transformed)
        
        # Calculate drift metrics
        drift_metrics = {
            "mean_prediction": float(np.mean(predictions)),
            "std_prediction": float(np.std(predictions)),
            "drift_score": self._calculate_drift_score(predictions),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        return {
            "drift_detected": drift_metrics["drift_score"] > 0.1,
            "metrics": drift_metrics
        }

    def _calculate_drift_score(self, recent_predictions: np.ndarray) -> float:
        """Calculate model drift score."""
        if not self.model or not self.model.training_history:
            return 0.0
        
        # Get historical predictions
        historical_metrics = [h['metrics'] for h in self.model.training_history]
        historical_rmse = [m['rmse'] for m in historical_metrics]
        
        # Calculate current RMSE
        current_rmse = np.std(recent_predictions)
        
        # Compare with historical performance
        drift_score = abs(current_rmse - np.mean(historical_rmse)) / np.std(historical_rmse)
        return float(drift_score)

    def load_latest_model(self) -> None:
        """Load the latest trained model."""
        # Find latest model file
        model_files = [f for f in os.listdir(self.model_dir) if f.startswith("model_")]
        if not model_files:
            raise RuntimeError("No trained models found")
        
        latest_model = max(model_files, key=lambda f: os.path.getmtime(os.path.join(self.model_dir, f)))
        model_path = os.path.join(self.model_dir, latest_model)
        
        # Load model
        self.model = EnsembleModel.load_model(model_path)