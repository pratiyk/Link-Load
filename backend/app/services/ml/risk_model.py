from typing import Dict, Any, Optional, List, Tuple
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor
import xgboost as xgb
import lightgbm as lgb
from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score
import optuna
import mlflow
import shap
import joblib
from pathlib import Path
from datetime import datetime

class RiskScoringModel:
    """Ensemble model for vulnerability risk scoring"""
    
    def __init__(self, model_dir: str = "test_models"):
        self.model_dir = Path(model_dir).resolve()
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.models = {}
        self.feature_importances = {}
        self.model_weights = {}

    def train(self, X: pd.DataFrame, y: pd.Series, experiment_name: str = "risk_scoring") -> Dict[str, float]:
        """Train the ensemble model and track with MLflow"""
        mlflow.set_experiment(experiment_name)
        
        with mlflow.start_run(run_name=f"ensemble_training_{datetime.now().strftime('%Y%m%d_%H%M%S')}"):
            # Split data
            X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # Train base models
            self.models['rf'] = self._train_random_forest(X_train, y_train, X_val, y_val)
            self.models['xgb'] = self._train_xgboost(X_train, y_train, X_val, y_val)
            self.models['lgb'] = self._train_lightgbm(X_train, y_train, X_val, y_val)
            
            # Calculate optimal weights
            predictions = {
                name: model.predict(X_val) 
                for name, model in self.models.items()
            }
            
            self.model_weights = self._optimize_weights(predictions, y_val)
            
            # Calculate ensemble predictions
            ensemble_pred = self._ensemble_predict(X_val)
            
            # Calculate metrics
            metrics = {
                'mse': mean_squared_error(y_val, ensemble_pred),
                'mae': mean_absolute_error(y_val, ensemble_pred),
                'r2': r2_score(y_val, ensemble_pred)
            }
            
            # Log metrics and parameters
            mlflow.log_metrics(metrics)
            mlflow.log_params({
                'rf_max_depth': self.models['rf'].get_params()['max_depth'],
                'xgb_learning_rate': self.models['xgb'].get_params()['learning_rate'],
                'lgb_num_leaves': self.models['lgb'].get_params()['num_leaves']
            })
            
            # Calculate and log feature importance
            self._calculate_feature_importance(X, y)
            
            # Save models
            self.save_models()
            
            return metrics

    def _train_random_forest(self, X_train, y_train, X_val, y_val) -> RandomForestRegressor:
        """Train and optimize Random Forest model"""
        def objective(trial):
            params = {
                'n_estimators': trial.suggest_int('n_estimators', 50, 300),
                'max_depth': trial.suggest_int('max_depth', 3, 15),
                'min_samples_split': trial.suggest_int('min_samples_split', 2, 10),
                'min_samples_leaf': trial.suggest_int('min_samples_leaf', 1, 5)
            }
            model = RandomForestRegressor(**params, random_state=42, n_jobs=-1)
            model.fit(X_train, y_train)
            pred = model.predict(X_val)
            return mean_squared_error(y_val, pred)

        study = optuna.create_study(direction='minimize')
        study.optimize(objective, n_trials=50)
        
        best_rf = RandomForestRegressor(**study.best_params, random_state=42, n_jobs=-1)
        best_rf.fit(X_train, y_train)
        return best_rf

    def _train_xgboost(self, X_train, y_train, X_val, y_val) -> xgb.XGBRegressor:
        """Train and optimize XGBoost model"""
        def objective(trial):
            params = {
                'max_depth': trial.suggest_int('max_depth', 3, 12),
                'learning_rate': trial.suggest_float('learning_rate', 0.001, 0.1, log=True),
                'n_estimators': trial.suggest_int('n_estimators', 100, 500),
                'min_child_weight': trial.suggest_int('min_child_weight', 1, 10),
                'subsample': trial.suggest_float('subsample', 0.6, 1.0),
                'colsample_bytree': trial.suggest_float('colsample_bytree', 0.6, 1.0),
                'reg_alpha': trial.suggest_float('reg_alpha', 1e-8, 1.0, log=True),
                'reg_lambda': trial.suggest_float('reg_lambda', 1e-8, 1.0, log=True),
                'base_score': float(y_train.mean())
            }
            eval_set = [(X_val, y_val)]
            model = xgb.XGBRegressor(**params)
            model.fit(X_train, y_train,
                     eval_set=eval_set)
            pred = np.array(model.predict(X_val))
            return float(mean_squared_error(y_val, pred))  # Convert prediction to numpy array

        study = optuna.create_study(direction='minimize')
        study.optimize(objective, n_trials=50)
        
        # Add base_score to best params
        best_params = study.best_params
        best_params['base_score'] = y_train.mean()
        best_params['enable_categorical'] = False
        
        best_xgb = xgb.XGBRegressor(**best_params, random_state=42)
        best_xgb.fit(X_train, y_train,
                 eval_set=[(X_val, y_val)])
        return best_xgb

    def _train_lightgbm(self, X_train, y_train, X_val, y_val) -> lgb.LGBMRegressor:
        """Train and optimize LightGBM model"""
        def objective(trial):
            params = {
                'num_leaves': trial.suggest_int('num_leaves', 20, 100),
                'learning_rate': trial.suggest_float('learning_rate', 0.001, 0.1, log=True),
                'n_estimators': trial.suggest_int('n_estimators', 100, 500),
                'min_child_samples': trial.suggest_int('min_child_samples', 5, 30),
                'subsample': trial.suggest_float('subsample', 0.6, 1.0),
                'colsample_bytree': trial.suggest_float('colsample_bytree', 0.6, 1.0),
                'reg_alpha': trial.suggest_float('reg_alpha', 1e-8, 1.0, log=True),
                'reg_lambda': trial.suggest_float('reg_lambda', 1e-8, 1.0, log=True),
                'feature_fraction': trial.suggest_float('feature_fraction', 0.6, 1.0),
                'min_data_in_bin': trial.suggest_int('min_data_in_bin', 3, 100)
            }
            model = lgb.LGBMRegressor(**params, random_state=42)
            model.fit(X_train, y_train,
                     eval_set=[(X_val, y_val)],
                     callbacks=[lgb.early_stopping(stopping_rounds=50)])
            pred = np.array(model.predict(X_val))
            return float(mean_squared_error(y_val, pred))

        study = optuna.create_study(direction='minimize')
        study.optimize(objective, n_trials=50)
        
        best_lgb = lgb.LGBMRegressor(**study.best_params, random_state=42)
        best_lgb.fit(X_train, y_train)
        return best_lgb

    def _optimize_weights(self, predictions: Dict[str, np.ndarray], y_true: np.ndarray) -> Dict[str, float]:
        """Optimize ensemble weights using Optuna"""
        def objective(trial):
            weights = {
                'rf': trial.suggest_float('rf_weight', 0, 1),
                'xgb': trial.suggest_float('xgb_weight', 0, 1),
                'lgb': trial.suggest_float('lgb_weight', 0, 1)
            }
            # Normalize weights
            total = sum(weights.values())
            weights = {k: v/total for k, v in weights.items()}
            
            # Calculate weighted prediction
            weighted_pred = sum(weights[name] * pred for name, pred in predictions.items())
            return mean_squared_error(y_true, weighted_pred)

        study = optuna.create_study(direction='minimize')
        study.optimize(objective, n_trials=100)
        
        # Get best weights and normalize
        weights = {
            'rf': study.best_params['rf_weight'],
            'xgb': study.best_params['xgb_weight'],
            'lgb': study.best_params['lgb_weight']
        }
        total = sum(weights.values())
        return {k: v/total for k, v in weights.items()}

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """Generate ensemble predictions"""
        return self._ensemble_predict(X)

    def _ensemble_predict(self, X: pd.DataFrame) -> np.ndarray:
        """Generate weighted ensemble predictions"""
        predictions = {
            name: model.predict(X) 
            for name, model in self.models.items()
        }
        # Convert predictions to numpy arrays and handle weighted sum properly
        weighted_sum = np.zeros(len(X))
        for name, pred in predictions.items():
            weighted_sum += self.model_weights[name] * np.array(pred)
        return weighted_sum

    def _calculate_feature_importance(self, X: pd.DataFrame, y: pd.Series):
        """Calculate and store feature importance using SHAP values"""
        for name, model in self.models.items():
            # Handle XGBoost models separately due to base_score issue
            if name == 'xgb':
                # Get feature importance directly from the model
                importance_vals = model.feature_importances_
                self.feature_importances[name] = dict(zip(X.columns, importance_vals))
            else:
                try:
                    explainer = shap.TreeExplainer(model)
                    shap_values = explainer.shap_values(X)
                    
                    if isinstance(shap_values, list):
                        shap_values = shap_values[0]  # For multi-output models
                        
                    feature_importance = np.abs(shap_values).mean(0)
                    self.feature_importances[name] = dict(zip(X.columns, feature_importance))
                except Exception as e:
                    # Fallback to built-in feature importance
                    importance_vals = model.feature_importances_
                    self.feature_importances[name] = dict(zip(X.columns, importance_vals))
            
            # Log to MLflow
            mlflow.log_dict(
                self.feature_importances[name], 
                f'feature_importance_{name}.json'
            )

    def _acquire_lock(self, file_path: Path, shared: bool = False) -> Any:
        """Acquire a file lock using msvcrt on Windows"""
        import msvcrt
        # Create file if it doesn't exist when in non-shared mode
        mode = 'rb' if shared else 'ab+'
        file_obj = open(file_path, mode)
        # Seek to beginning for reading/writing
        file_obj.seek(0)
        try:
            msvcrt.locking(file_obj.fileno(), msvcrt.LK_NBLCK if shared else msvcrt.LK_NBRLCK, 1)
        except IOError:
            file_obj.close()
            raise IOError(f"Could not acquire {'shared' if shared else 'exclusive'} lock on {file_path}")
        return file_obj

    def _release_lock(self, file_obj: Any) -> None:
        """Release a file lock using msvcrt on Windows"""
        import msvcrt
        if file_obj:
            try:
                msvcrt.locking(file_obj.fileno(), msvcrt.LK_UNLCK, 1)
            finally:
                file_obj.close()

    def _compute_checksum(self, file_path: Path) -> str:
        """Compute SHA256 checksum of a file"""
        import hashlib
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _save_file_atomically(self, obj: Any, file_path: Path, backup: bool = True) -> None:
        """Save a file atomically with backup and checksum verification"""
        import tempfile
        import os
        import shutil

        # Ensure absolute path and create directories
        file_path = Path(file_path).resolve()
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        temp_file = None
        lock_file = None
        backup_path = None
        
        try:
            # Create a temporary file in the same directory
            temp_file = str(file_path) + '.tmp'
            
            # Save to temporary file
            joblib.dump(obj, temp_file)
            
            # Compute checksum
            checksum = self._compute_checksum(Path(temp_file))
            
            # Create backup if requested and original exists
            if backup and file_path.exists():
                backup_path = str(file_path) + '.bak'
                try:
                    shutil.copy2(str(file_path), backup_path)
                except Exception as e:
                    print(f"Warning: Failed to create backup: {e}")
            
            # Atomic rename
            if os.path.exists(str(file_path)):
                os.replace(temp_file, str(file_path))  # Atomic on Windows
            else:
                os.rename(temp_file, str(file_path))  # Atomic on Windows
            
            # Verify checksum
            if self._compute_checksum(file_path) != checksum:
                # Restore from backup if verification fails
                if backup_path and os.path.exists(backup_path):
                    os.replace(backup_path, str(file_path))
                raise IOError("Checksum verification failed after save")
                
        except Exception as e:
            # On failure, cleanup temp file
            if temp_file and os.path.exists(temp_file):
                try:
                    os.unlink(temp_file)
                except:
                    pass
            raise e
                    
        finally:
            # Cleanup backup if save succeeded
            if backup_path and os.path.exists(backup_path):
                try:
                    os.unlink(backup_path)
                except:
                    pass

    def save_models(self):
        """Save all models and metadata with atomic operations and verification"""
        # Create version metadata
        version_info = {
            'timestamp': datetime.now().isoformat(),
            'models': {name: str(model.__class__.__name__) for name, model in self.models.items()},
            'weights': self.model_weights,
            'feature_importances': {k: len(v) for k, v in self.feature_importances.items()}
        }
        
        # Ensure model directory exists
        self.model_dir = Path(self.model_dir).resolve()
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate timestamp and sanitize
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        save_dir = self.model_dir / timestamp
        save_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            # Save version info first
            self._save_file_atomically(version_info, save_dir / 'version.joblib')
            
            # Save individual models
            for name, model in self.models.items():
                self._save_file_atomically(model, save_dir / f'{name}_model.joblib')
            
            # Save weights and feature importance
            self._save_file_atomically(self.model_weights, save_dir / 'model_weights.joblib')
            self._save_file_atomically(self.feature_importances, save_dir / 'feature_importance.joblib')
            
            # Update latest copies directly (no symlinks on Windows)
            for name in self.models.keys():
                latest_path = self.model_dir / f'{name}_model_latest.joblib'
                # Just save directly with atomic operation
                self._save_file_atomically(self.models[name], latest_path, backup=True)
            
            # Save latest version info
            version_latest = self.model_dir / 'version_latest.joblib'
            self._save_file_atomically(version_info, version_latest)
            
        except Exception as e:
            import shutil
            # Cleanup on failure
            if save_dir.exists():
                try:
                    shutil.rmtree(save_dir)
                except:
                    pass
            raise RuntimeError(f"Failed to save models: {str(e)}")

    def _load_file_safely(self, file_path: Path) -> Any:
        """Load a file with checksum verification and locking"""
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        file_obj = None
        try:
            # Acquire shared lock for reading
            file_obj = self._acquire_lock(file_path, shared=True)
            
            # Load data
            data = joblib.load(file_path)
            
            # If backup exists, verify checksum
            backup_path = file_path.with_suffix(file_path.suffix + '.bak')
            if backup_path.exists():
                main_checksum = self._compute_checksum(file_path)
                backup_checksum = self._compute_checksum(backup_path)
                
                # If main file is corrupted, restore from backup
                if main_checksum != backup_checksum:
                    import os
                    print(f"Warning: File corruption detected in {file_path}, restoring from backup")
                    self._release_lock(file_obj)
                    file_obj = None
                    
                    # Acquire exclusive lock to restore backup
                    with self._acquire_lock(file_path, shared=False) as lock:
                        os.replace(str(backup_path), str(file_path))
                        data = joblib.load(file_path)
            
            return data
            
        finally:
            # Release lock
            if file_obj:
                self._release_lock(file_obj)
    
    def load_models(self, timestamp: Optional[str] = None):
        """Load models from disk with verification and fallback"""
        try:
            if timestamp:
                load_dir = self.model_dir / timestamp
                if not load_dir.exists():
                    raise FileNotFoundError(f"Version {timestamp} not found")
                
                # Verify version info
                version_info = self._load_file_safely(load_dir / 'version.joblib')
                
                # Load models
                for name, model_type in version_info['models'].items():
                    model_path = load_dir / f'{name}_model.joblib'
                    self.models[name] = self._load_file_safely(model_path)
                    
                    # Verify model type matches
                    if str(self.models[name].__class__.__name__) != model_type:
                        raise ValueError(f"Model type mismatch for {name}")
                
                # Load weights and importance
                self.model_weights = self._load_file_safely(load_dir / 'model_weights.joblib')
                self.feature_importances = self._load_file_safely(load_dir / 'feature_importance.joblib')
                
            else:
                # Load latest with fallback to most recent version
                version_latest = self.model_dir / 'version_latest.joblib'
                
                try:
                    version_info = self._load_file_safely(version_latest)
                    
                    # Load models
                    for name in ['rf', 'xgb', 'lgb']:
                        model_path = self.model_dir / f'{name}_model_latest.joblib'
                        self.models[name] = self._load_file_safely(model_path)
                    
                    # Load weights and importance
                    weights_path = self.model_dir / 'model_weights_latest.joblib'
                    importance_path = self.model_dir / 'feature_importance_latest.joblib'
                    
                    self.model_weights = self._load_file_safely(weights_path)
                    self.feature_importances = self._load_file_safely(importance_path)
                    
                except Exception as e:
                    print(f"Warning: Failed to load latest models: {str(e)}")
                    print("Attempting to load most recent version...")
                    
                    # Find most recent version
                    versions = [d for d in self.model_dir.iterdir() if d.is_dir()]
                    if not versions:
                        raise FileNotFoundError("No model versions found")
                        
                    latest_version = sorted(versions)[-1]
                    self.load_models(latest_version.name)
                    
        except Exception as e:
            raise RuntimeError(f"Failed to load models: {str(e)}")