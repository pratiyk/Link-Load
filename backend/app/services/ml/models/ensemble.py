"""ML model implementations for vulnerability risk assessment."""
from typing import Dict, List, Any, Optional, Tuple
import numpy as np
import pandas as pd
from datetime import datetime
import joblib

# Optional ML dependencies - make imports conditional
try:
    import mlflow
    MLFLOW_AVAILABLE = True
except ImportError:
    mlflow = None  # type: ignore
    MLFLOW_AVAILABLE = False

try:
    import torch
    import torch.nn as nn
    TORCH_AVAILABLE = True
except ImportError:
    torch = None  # type: ignore
    nn = None  # type: ignore
    TORCH_AVAILABLE = False

from sklearn.model_selection import TimeSeriesSplit
from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score
from xgboost import XGBRegressor
from lightgbm import LGBMRegressor

try:
    from catboost import CatBoostRegressor
    CATBOOST_AVAILABLE = True
except ImportError:
    CatBoostRegressor = None  # type: ignore
    CATBOOST_AVAILABLE = False

try:
    import optuna
    OPTUNA_AVAILABLE = True
except ImportError:
    optuna = None  # type: ignore
    OPTUNA_AVAILABLE = False

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    shap = None  # type: ignore
    SHAP_AVAILABLE = False


# Only define DeepRiskNet if torch is available
if TORCH_AVAILABLE:
    class DeepRiskNet(nn.Module):
        """Deep neural network for risk scoring."""
        
        def __init__(self, input_size: int, hidden_sizes: List[int] = [64, 32, 16]):
            super().__init__()
            layers = []
            prev_size = input_size
            
            for hidden_size in hidden_sizes:
                layers.extend([
                    nn.Linear(prev_size, hidden_size),
                    nn.ReLU(),
                    nn.BatchNorm1d(hidden_size),
                    nn.Dropout(0.3)
                ])
                prev_size = hidden_size
            
            layers.append(nn.Linear(hidden_sizes[-1], 1))
            self.network = nn.Sequential(*layers)

        def forward(self, x):
            return self.network(x)
else:
    # Fallback stub when torch is not available
    class DeepRiskNet:  # type: ignore
        """Stub DeepRiskNet when torch is not available."""
        def __init__(self, *args, **kwargs):
            pass

class EnsembleModel:
    """Stacked ensemble model for vulnerability risk scoring."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or self._default_config()
        self.base_models = []
        self.meta_model = None
        self.feature_importance = {}
        self.shap_values = None
        self.model_metrics = {}
        self.training_history = []

    def _default_config(self) -> Dict[str, Any]:
        """Default model configuration."""
        return {
            'xgboost_params': {
                'n_estimators': 100,
                'learning_rate': 0.1,
                'max_depth': 5,
                'subsample': 0.8,
                'colsample_bytree': 0.8
            },
            'lightgbm_params': {
                'n_estimators': 100,
                'learning_rate': 0.1,
                'num_leaves': 31,
                'subsample': 0.8
            },
            'catboost_params': {
                'iterations': 100,
                'learning_rate': 0.1,
                'depth': 5
            },
            'deep_learning_params': {
                'hidden_sizes': [64, 32, 16],
                'learning_rate': 0.001,
                'batch_size': 32,
                'epochs': 100
            }
        }

    def optimize_hyperparameters(self, X: np.ndarray, y: np.ndarray, n_trials: int = 50) -> Dict[str, Any]:
        """Optimize hyperparameters using Optuna."""
        if not OPTUNA_AVAILABLE:
            return self.config  # Return default config if optuna not available
            
        def objective(trial):
            params = {
                'xgboost_params': {
                    'n_estimators': trial.suggest_int('xgb_n_estimators', 50, 300),
                    'learning_rate': trial.suggest_float('xgb_lr', 0.01, 0.3),
                    'max_depth': trial.suggest_int('xgb_depth', 3, 10),
                    'subsample': trial.suggest_float('xgb_subsample', 0.6, 1.0),
                    'colsample_bytree': trial.suggest_float('xgb_colsample', 0.6, 1.0)
                },
                'lightgbm_params': {
                    'n_estimators': trial.suggest_int('lgb_n_estimators', 50, 300),
                    'learning_rate': trial.suggest_float('lgb_lr', 0.01, 0.3),
                    'num_leaves': trial.suggest_int('lgb_leaves', 15, 63),
                    'subsample': trial.suggest_float('lgb_subsample', 0.6, 1.0)
                }
            }
            
            self.config.update(params)
            cv_scores = self._cross_validate(X, y)
            return np.mean(cv_scores['test_rmse'])

        study = optuna.create_study(direction='minimize')
        study.optimize(objective, n_trials=n_trials)
        
        self.config.update(study.best_params)
        return study.best_params

    def _cross_validate(self, X: np.ndarray, y: np.ndarray, n_splits: int = 5) -> Dict[str, List[float]]:
        """Perform time series cross-validation."""
        tscv = TimeSeriesSplit(n_splits=n_splits)
        scores = {
            'train_rmse': [],
            'test_rmse': [],
            'train_mae': [],
            'test_mae': [],
            'train_r2': [],
            'test_r2': []
        }
        
        for train_idx, test_idx in tscv.split(X):
            X_train, X_test = X[train_idx], X[test_idx]
            y_train, y_test = y[train_idx], y[test_idx]
            
            self.fit(X_train, y_train)
            y_train_pred = self.predict(X_train)
            y_test_pred = self.predict(X_test)
            
            scores['train_rmse'].append(np.sqrt(mean_squared_error(y_train, y_train_pred)))
            scores['test_rmse'].append(np.sqrt(mean_squared_error(y_test, y_test_pred)))
            scores['train_mae'].append(mean_absolute_error(y_train, y_train_pred))
            scores['test_mae'].append(mean_absolute_error(y_test, y_test_pred))
            scores['train_r2'].append(r2_score(y_train, y_train_pred))
            scores['test_r2'].append(r2_score(y_test, y_test_pred))
        
        return scores

    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        """Train the ensemble model."""
        # Initialize and train base models
        self.base_models = [
            ('xgb', XGBRegressor(**self.config['xgboost_params'])),
            ('lgb', LGBMRegressor(**self.config['lightgbm_params'])),
        ]
        
        # Add CatBoost only if available
        if CATBOOST_AVAILABLE:
            self.base_models.append(
                ('cat', CatBoostRegressor(**self.config['catboost_params'], verbose=False))
            )
        
        # Train deep learning model if torch and GPU is available
        if TORCH_AVAILABLE and torch.cuda.is_available():
            self._train_deep_model(X, y)
        
        # Generate base model predictions
        base_predictions = np.column_stack([
            model.fit(X, y).predict(X) for name, model in self.base_models
        ])
        
        # Train meta-model
        self.meta_model = XGBRegressor(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=3
        )
        self.meta_model.fit(base_predictions, y)
        
        # Calculate feature importance
        self._calculate_feature_importance()
        
        # Log training metrics
        self._log_training_metrics(X, y)

    def _train_deep_model(self, X: np.ndarray, y: np.ndarray) -> None:
        """Train deep learning model."""
        if not TORCH_AVAILABLE:
            return
            
        params = self.config['deep_learning_params']
        model = DeepRiskNet(X.shape[1], params['hidden_sizes'])
        
        if torch.cuda.is_available():
            model = model.cuda()
            X_tensor = torch.FloatTensor(X).cuda()
            y_tensor = torch.FloatTensor(y).cuda()
        else:
            X_tensor = torch.FloatTensor(X)
            y_tensor = torch.FloatTensor(y)
        
        criterion = nn.MSELoss()
        optimizer = torch.optim.Adam(model.parameters(), lr=params['learning_rate'])
        
        dataset = torch.utils.data.TensorDataset(X_tensor, y_tensor.reshape(-1, 1))
        dataloader = torch.utils.data.DataLoader(
            dataset, batch_size=params['batch_size'], shuffle=True
        )
        
        for epoch in range(params['epochs']):
            model.train()
            for batch_X, batch_y in dataloader:
                optimizer.zero_grad()
                outputs = model(batch_X)
                loss = criterion(outputs, batch_y)
                loss.backward()
                optimizer.step()
        
        self.base_models.append(('deep', model))

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Generate ensemble predictions."""
        predictions = []
        for name, model in self.base_models:
            if TORCH_AVAILABLE and isinstance(model, DeepRiskNet):
                tensor_input = torch.FloatTensor(X).cuda() if torch.cuda.is_available() else torch.FloatTensor(X)
                predictions.append(model(tensor_input).detach().cpu().numpy().flatten())
            else:
                predictions.append(model.predict(X))
        
        base_predictions = np.column_stack(predictions)
        return self.meta_model.predict(base_predictions)

    def predict_proba(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Generate predictions with confidence intervals."""
        predictions = []
        for name, model in self.base_models:
            if TORCH_AVAILABLE and isinstance(model, DeepRiskNet):
                tensor_input = torch.FloatTensor(X).cuda() if torch.cuda.is_available() else torch.FloatTensor(X)
                pred = model(tensor_input).detach().cpu().numpy().flatten()
            else:
                pred = model.predict(X)
            predictions.append(pred)
        
        base_predictions = np.column_stack(predictions)
        mean_pred = self.meta_model.predict(base_predictions)
        std_pred = np.std(predictions, axis=0)
        
        return mean_pred, std_pred

    def _calculate_feature_importance(self) -> None:
        """Calculate and store feature importance."""
        for name, model in self.base_models:
            if not isinstance(model, DeepRiskNet):
                self.feature_importance[name] = model.feature_importances_

    def explain_prediction(self, X: np.ndarray) -> Dict[str, Any]:
        """Generate SHAP explanations for predictions."""
        if not SHAP_AVAILABLE:
            return {
                'shap_values': None,
                'expected_value': None,
                'note': 'SHAP not available - install shap package for explanations'
            }
            
        explainer = shap.TreeExplainer(self.base_models[0][1])  # Use XGBoost for SHAP
        shap_values = explainer.shap_values(X)
        self.shap_values = shap_values
        
        return {
            'shap_values': shap_values,
            'expected_value': explainer.expected_value
        }

    def _log_training_metrics(self, X: np.ndarray, y: np.ndarray) -> None:
        """Log training metrics to MLflow."""
        predictions = self.predict(X)
        metrics = {
            'rmse': np.sqrt(mean_squared_error(y, predictions)),
            'mae': mean_absolute_error(y, predictions),
            'r2': r2_score(y, predictions)
        }
        
        self.model_metrics.update(metrics)
        self.training_history.append({
            'timestamp': datetime.now().isoformat(),
            'metrics': metrics
        })
        
        if MLFLOW_AVAILABLE:
            mlflow.log_metrics(metrics)

    def save_model(self, path: str) -> None:
        """Save model to disk."""
        model_data = {
            'base_models': self.base_models,
            'meta_model': self.meta_model,
            'config': self.config,
            'feature_importance': self.feature_importance,
            'metrics': self.model_metrics,
            'training_history': self.training_history
        }
        joblib.dump(model_data, path)

    @classmethod
    def load_model(cls, path: str) -> 'EnsembleModel':
        """Load model from disk."""
        model_data = joblib.load(path)
        model = cls(model_data['config'])
        model.base_models = model_data['base_models']
        model.meta_model = model_data['meta_model']
        model.feature_importance = model_data['feature_importance']
        model.model_metrics = model_data['metrics']
        model.training_history = model_data['training_history']
        return model