import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
import seaborn as sns
import sys
import os

# Add the project root to Python path
project_root = Path(__file__).parent.parent.parent
sys.path.append(str(project_root))

from app.services.ml.pipeline import MLPipeline
from scripts.generate_synthetic_data import generate_synthetic_data

def run_ml_workflow(use_synthetic: bool = True, n_samples: int = 1000):
    """Run the complete ML workflow"""
    print("Step 1: Generating training data...")
    if use_synthetic:
        generate_synthetic_data(n_samples)
        data = pd.read_csv('synthetic_training_data.csv')
    else:
        # Use existing data from database
        from scripts.export_training_data import export_training_data
        export_training_data()
        data = pd.read_csv('training_data.csv')

    print(f"Generated {len(data)} training samples")

    # Split into train/validation/test
    train_data, test_data = train_test_split(data, test_size=0.2, random_state=42)
    
    print("\nStep 2: Training ML pipeline...")
    pipeline = MLPipeline()
    metrics = pipeline.train_pipeline(train_data)
    
    print("\nTraining metrics:")
    for metric, value in metrics.items():
        print(f"{metric}: {value:.4f}")
    
    print("\nStep 3: Evaluating on test data...")
    test_metrics = pipeline.evaluate_performance(test_data)
    
    print("\nTest metrics:")
    for metric, value in test_metrics.items():
        print(f"{metric}: {value:.4f}")
    
    print("\nStep 4: Analyzing feature importance...")
    feature_importance = pipeline.get_feature_importance()
    
    # Create feature importance plots
    plt.figure(figsize=(12, 6))
    for model_name, importance in feature_importance.items():
        plt.subplot(1, 3, list(feature_importance.keys()).index(model_name) + 1)
        
        # Sort importance values
        sorted_importance = dict(sorted(importance.items(), key=lambda x: x[1], reverse=True))
        
        plt.barh(list(sorted_importance.keys()), list(sorted_importance.values()))
        plt.title(f'{model_name.upper()} Feature Importance')
        plt.xlabel('Importance Score')
    
    plt.tight_layout()
    plt.savefig('feature_importance.png')
    
    print("\nStep 5: Saving the pipeline...")
    pipeline.save_pipeline()
    
    print("\nWorkflow completed successfully!")
    print("Feature importance plot saved as 'feature_importance.png'")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Run ML workflow for risk scoring')
    parser.add_argument('--synthetic', action='store_true', help='Use synthetic data instead of database data')
    parser.add_argument('--samples', type=int, default=1000, help='Number of synthetic samples to generate')
    
    args = parser.parse_args()
    run_ml_workflow(use_synthetic=args.synthetic, n_samples=args.samples)