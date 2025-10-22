import mlflow
import pandas as pd
from pathlib import Path
from typing import Optional, Dict, Any
import logging
from datetime import datetime
from .feature_engineering import FeatureEngineer
from .risk_model import RiskScoringModel

logger = logging.getLogger(__name__)

class MLPipeline:
    """End-to-end ML pipeline for risk scoring"""
    
    def __init__(self, model_dir: str = "models"):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.feature_engineer = FeatureEngineer()
        self.model = RiskScoringModel(model_dir)
        
        # Initialize MLflow
        mlflow.set_tracking_uri('sqlite:///mlflow.db')

    def train_pipeline(self, training_data: pd.DataFrame) -> Dict[str, float]:
        """Train the complete pipeline"""
        try:
            logger.info("Starting pipeline training")
            
            # Feature engineering
            feature_set = self.feature_engineer.prepare_features(training_data, fit=True)
            
            # Model training
            metrics = self.model.train(feature_set.X, feature_set.y)
            
            logger.info(f"Pipeline training completed. Metrics: {metrics}")
            return metrics
            
        except Exception as e:
            logger.error(f"Error in pipeline training: {e}")
            raise

    def predict(self, data: pd.DataFrame) -> pd.Series:
        """Generate predictions using the trained pipeline"""
        try:
            # Prepare features
            feature_set = self.feature_engineer.prepare_features(data, fit=False)
            
            # Generate predictions
            predictions = self.model.predict(feature_set.X)
            
            return pd.Series(predictions, index=data.index)
            
        except Exception as e:
            logger.error(f"Error in prediction: {e}")
            raise

    def get_feature_importance(self) -> Dict[str, Dict[str, float]]:
        """Get feature importance for each model"""
        return self.model.feature_importances

    def evaluate_performance(self, test_data: pd.DataFrame) -> Dict[str, float]:
        """Evaluate model performance on test data"""
        try:
            # Prepare features
            feature_set = self.feature_engineer.prepare_features(test_data, fit=False)
            
            # Generate predictions
            predictions = self.model.predict(feature_set.X)
            
            # Calculate metrics
            from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score
            metrics = {
                'test_mse': mean_squared_error(feature_set.y, predictions),
                'test_mae': mean_absolute_error(feature_set.y, predictions),
                'test_r2': r2_score(feature_set.y, predictions)
            }
            
            logger.info(f"Model evaluation metrics: {metrics}")
            return metrics
            
        except Exception as e:
            logger.error(f"Error in performance evaluation: {e}")
            raise

    def save_pipeline(self):
        """Save the complete pipeline"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        save_dir = self.model_dir / timestamp
        save_dir.mkdir(parents=True, exist_ok=True)
        
        # Save the feature engineering components
        pd.to_pickle(self.feature_engineer, save_dir / 'feature_engineer.pkl')
        
        # Save the model
        self.model.save_models()
        
        logger.info(f"Pipeline saved to {save_dir}")

    def load_pipeline(self, timestamp: Optional[str] = None):
        """Load the complete pipeline"""
        try:
            if timestamp:
                load_dir = self.model_dir / timestamp
                
                # Load feature engineering
                self.feature_engineer = pd.read_pickle(load_dir / 'feature_engineer.pkl')
                
                # Load model
                self.model.load_models(timestamp)
            else:
                # Load latest
                latest_fe = sorted(self.model_dir.glob('*/feature_engineer.pkl'))[-1]
                self.feature_engineer = pd.read_pickle(latest_fe)
                self.model.load_models()
                
            logger.info("Pipeline loaded successfully")
            
        except Exception as e:
            logger.error(f"Error loading pipeline: {e}")
            raise