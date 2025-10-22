import numpy as np
import pandas as pd
from risk_model import RiskScoringModel

# Create sample data
np.random.seed(42)
X = pd.DataFrame({
    'feature1': np.random.normal(0, 1, 100),
    'feature2': np.random.normal(0, 1, 100),
    'feature3': np.random.normal(0, 1, 100)
})
y = 0.3 * X['feature1'] + 0.5 * X['feature2'] + 0.2 * X['feature3'] + np.random.normal(0, 0.1, 100)

# Create and train model
model = RiskScoringModel(model_dir="test_models")
model.train(X, y)

# Test saving
print("Testing model save...")
model.save_models()
print("Model saved successfully!")