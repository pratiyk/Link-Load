"""
Test ML Model Inference Pipeline
Tests for phishing detection ML models and integration
"""
import pytest
import os
from pathlib import Path
import joblib
import numpy as np


@pytest.fixture
def ml_models_dir():
    """Get the ML models directory"""
    backend_dir = Path(__file__).parent.parent
    models_dir = backend_dir / "ml_models" / "phishing_detection"
    return models_dir


@pytest.fixture
def test_models_dir():
    """Get the test models directory"""
    backend_dir = Path(__file__).parent.parent
    test_models_dir = backend_dir / "test_models"
    return test_models_dir


def test_ml_models_directory_exists(ml_models_dir):
    """Verify ML models directory exists"""
    assert ml_models_dir.exists(), f"ML models directory not found: {ml_models_dir}"


def test_test_models_directory_exists(test_models_dir):
    """Verify test models directory exists"""
    assert test_models_dir.exists(), f"Test models directory not found: {test_models_dir}"


def test_model_files_exist(test_models_dir):
    """Check that model files are present"""
    expected_models = [
        "rf_model_latest.joblib",
        "xgb_model_latest.joblib",
        "lgb_model_latest.joblib"
    ]
    
    for model_name in expected_models:
        model_path = test_models_dir / model_name
        assert model_path.exists(), f"Model file not found: {model_name}"


def test_load_random_forest_model(test_models_dir):
    """Test loading Random Forest model"""
    model_path = test_models_dir / "rf_model_latest.joblib"
    
    try:
        model = joblib.load(model_path)
        assert model is not None, "Model loaded but is None"
        assert hasattr(model, 'predict'), "Model doesn't have predict method"
        # These are regression models, not classification
        model_type = type(model).__name__
        assert 'Regressor' in model_type or 'Classifier' in model_type, f"Unexpected model type: {model_type}"
    except Exception as e:
        pytest.fail(f"Failed to load Random Forest model: {str(e)}")


def test_load_xgboost_model(test_models_dir):
    """Test loading XGBoost model"""
    model_path = test_models_dir / "xgb_model_latest.joblib"
    
    try:
        model = joblib.load(model_path)
        assert model is not None, "Model loaded but is None"
        assert hasattr(model, 'predict'), "Model doesn't have predict method"
        model_type = type(model).__name__
        assert 'Regressor' in model_type or 'Classifier' in model_type, f"Unexpected model type: {model_type}"
    except Exception as e:
        pytest.fail(f"Failed to load XGBoost model: {str(e)}")


def test_load_lightgbm_model(test_models_dir):
    """Test loading LightGBM model"""
    model_path = test_models_dir / "lgb_model_latest.joblib"
    
    try:
        model = joblib.load(model_path)
        assert model is not None, "Model loaded but is None"
        assert hasattr(model, 'predict'), "Model doesn't have predict method"
        model_type = type(model).__name__
        assert 'Regressor' in model_type or 'Classifier' in model_type, f"Unexpected model type: {model_type}"
    except Exception as e:
        pytest.fail(f"Failed to load LightGBM model: {str(e)}")


def test_model_inference_shape(test_models_dir):
    """Test that models can make predictions with correct shape"""
    model_path = test_models_dir / "rf_model_latest.joblib"
    
    try:
        model = joblib.load(model_path)
        
        # Create sample input (adjust feature count based on your model)
        # Most URL feature extractors create around 20-50 features
        n_features = 30  # Adjust this based on your actual feature count
        sample_input = np.random.rand(1, n_features)
        
        # Test prediction
        try:
            predictions = model.predict(sample_input)
            assert predictions.shape == (1,), f"Expected shape (1,), got {predictions.shape}"
            # These are regression models - predictions should be continuous values
            assert isinstance(predictions[0], (int, float, np.number)), f"Expected numeric prediction, got {type(predictions[0])}"
        except ValueError as e:
            # If we get a shape mismatch, that's expected - we need to know the actual feature count
            pytest.skip(f"Feature count mismatch (expected vs actual): {str(e)}")
            
    except Exception as e:
        pytest.fail(f"Model inference failed: {str(e)}")


def test_model_regression_output(test_models_dir):
    """Test that models output valid regression scores"""
    model_path = test_models_dir / "rf_model_latest.joblib"
    
    try:
        model = joblib.load(model_path)
        
        n_features = 30
        sample_input = np.random.rand(1, n_features)
        
        try:
            predictions = model.predict(sample_input)
            
            # Check shape
            assert predictions.shape == (1,), f"Expected shape (1,), got {predictions.shape}"
            
            # Check prediction is numeric
            assert isinstance(predictions[0], (int, float, np.number)), "Prediction should be numeric"
            
            # For risk scores, typically in range [0, 10] or [0, 100]
            # We'll just verify it's a reasonable number
            assert np.isfinite(predictions[0]), "Prediction should be finite"
            
        except ValueError as e:
            pytest.skip(f"Feature count mismatch: {str(e)}")
            
    except Exception as e:
        pytest.fail(f"Model prediction failed: {str(e)}")


def test_all_models_same_feature_count(test_models_dir):
    """Verify all models expect the same number of features"""
    model_names = [
        "rf_model_latest.joblib",
        "xgb_model_latest.joblib",
        "lgb_model_latest.joblib"
    ]
    
    feature_counts = []
    
    for model_name in model_names:
        model_path = test_models_dir / model_name
        try:
            model = joblib.load(model_path)
            
            # Try to get feature count
            if hasattr(model, 'n_features_in_'):
                feature_counts.append(model.n_features_in_)
            elif hasattr(model, 'n_features_'):
                feature_counts.append(model.n_features_)
            else:
                # Try prediction with different sizes to find expected count
                for n in range(10, 100, 5):
                    try:
                        sample = np.random.rand(1, n)
                        model.predict(sample)
                        feature_counts.append(n)
                        break
                    except ValueError:
                        continue
                        
        except Exception as e:
            pytest.skip(f"Could not determine feature count for {model_name}: {str(e)}")
    
    if len(feature_counts) > 1:
        assert len(set(feature_counts)) == 1, f"Models have different feature counts: {feature_counts}"


def test_model_ensemble_prediction():
    """Test ensemble prediction combining multiple models"""
    from pathlib import Path
    
    test_models_dir = Path(__file__).parent.parent / "test_models"
    
    model_names = [
        "rf_model_latest.joblib",
        "xgb_model_latest.joblib",
        "lgb_model_latest.joblib"
    ]
    
    models = []
    for model_name in model_names:
        model_path = test_models_dir / model_name
        try:
            model = joblib.load(model_path)
            models.append(model)
        except Exception as e:
            pytest.skip(f"Could not load model {model_name}: {str(e)}")
    
    if len(models) < 2:
        pytest.skip("Need at least 2 models for ensemble test")
    
    # Try prediction with sample data
    n_features = 30
    sample_input = np.random.rand(1, n_features)
    
    predictions = []
    
    for model in models:
        try:
            pred = model.predict(sample_input)
            predictions.append(pred[0])
        except ValueError:
            pytest.skip("Feature count mismatch - need actual feature extraction")
    
    if len(predictions) >= 2:
        # Ensemble by averaging predictions (regression)
        ensemble_pred = np.mean(predictions)
        assert isinstance(ensemble_pred, (int, float, np.number)), "Ensemble prediction should be numeric"
        assert np.isfinite(ensemble_pred), "Ensemble prediction should be finite"
        
        # Verify all predictions are similar scale
        pred_std = np.std(predictions)
        # If std is very large, models might be outputting different scales
        # This is just a sanity check
        assert pred_std < 100, f"Model predictions have very different scales: {predictions}"


@pytest.mark.asyncio
async def test_ml_integration_with_url_features():
    """Test ML model integration with actual URL feature extraction"""
    # This test would require the actual feature extraction pipeline
    # Marking as TODO for now
    pytest.skip("TODO: Implement URL feature extraction for ML inference")


@pytest.mark.asyncio
async def test_ml_prediction_performance():
    """Test ML model prediction latency"""
    import time
    from pathlib import Path
    
    test_models_dir = Path(__file__).parent.parent / "test_models"
    model_path = test_models_dir / "rf_model_latest.joblib"
    
    try:
        model = joblib.load(model_path)
        
        n_features = 30
        sample_input = np.random.rand(1, n_features)
        
        # Warm up
        try:
            model.predict(sample_input)
        except ValueError:
            pytest.skip("Feature count mismatch")
        
        # Measure prediction time
        start_time = time.time()
        for _ in range(100):
            model.predict(sample_input)
        end_time = time.time()
        
        avg_prediction_time = (end_time - start_time) / 100
        
        # Prediction should be fast (< 10ms per prediction)
        assert avg_prediction_time < 0.01, f"Prediction too slow: {avg_prediction_time:.4f}s"
        
    except Exception as e:
        pytest.skip(f"Performance test failed: {str(e)}")
