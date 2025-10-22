import os
import pytest
from pathlib import Path

@pytest.fixture(autouse=True)
def set_test_env():
    """Automatically set environment variables for all tests"""
    test_env_file = Path(__file__).parent / ".env.test"
    
    # Read and set environment variables
    with open(test_env_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
                
            key, value = line.split("=", 1)
            os.environ[key.strip()] = value.strip()