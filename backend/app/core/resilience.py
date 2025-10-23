from functools import wraps
import asyncio
from typing import Callable, Any, Optional
from loguru import logger
import time

class RetryConfig:
    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 30.0,
        exponential: bool = True,
        exceptions: tuple = (Exception,)
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential = exponential
        self.exceptions = exceptions

def with_retry(
    retry_config: Optional[RetryConfig] = None,
    on_retry: Optional[Callable[[Exception, int], Any]] = None
):
    """Decorator for retrying failed operations"""
    if retry_config is None:
        retry_config = RetryConfig()

    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(retry_config.max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except retry_config.exceptions as e:
                    last_exception = e
                    if attempt == retry_config.max_retries:
                        raise
                        
                    if on_retry:
                        on_retry(e, attempt + 1)
                        
                    delay = calculate_delay(attempt, retry_config)
                    logger.warning(
                        f"Operation failed: {str(e)}. "
                        f"Retrying in {delay:.1f}s (attempt {attempt + 1}/{retry_config.max_retries})"
                    )
                    await asyncio.sleep(delay)
                    
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(retry_config.max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except retry_config.exceptions as e:
                    last_exception = e
                    if attempt == retry_config.max_retries:
                        raise
                        
                    if on_retry:
                        on_retry(e, attempt + 1)
                        
                    delay = calculate_delay(attempt, retry_config)
                    logger.warning(
                        f"Operation failed: {str(e)}. "
                        f"Retrying in {delay:.1f}s (attempt {attempt + 1}/{retry_config.max_retries})"
                    )
                    time.sleep(delay)
                    
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    return decorator

def calculate_delay(attempt: int, config: RetryConfig) -> float:
    """Calculate delay between retries"""
    if config.exponential:
        delay = config.base_delay * (2 ** attempt)
    else:
        delay = config.base_delay
        
    return min(delay, config.max_delay)

class CircuitBreaker:
    def __init__(
        self,
        failure_threshold: int = 5,
        reset_timeout: float = 60.0,
        half_open_timeout: float = 30.0
    ):
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.half_open_timeout = half_open_timeout
        
        self.failures = 0
        self.last_failure_time = 0
        self.state = "closed"  # closed, open, or half-open
        
    def can_execute(self) -> bool:
        """Check if operation can be executed"""
        current_time = time.time()
        
        if self.state == "open":
            if current_time - self.last_failure_time >= self.reset_timeout:
                self.state = "half-open"
                return True
            return False
            
        return True
        
    def record_success(self):
        """Record successful operation"""
        self.failures = 0
        self.state = "closed"
        
    def record_failure(self):
        """Record failed operation"""
        current_time = time.time()
        self.failures += 1
        self.last_failure_time = current_time
        
        if self.failures >= self.failure_threshold:
            self.state = "open"
            
    def __call__(self, func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            if not self.can_execute():
                raise Exception("Circuit breaker is open")
                
            try:
                result = await func(*args, **kwargs)
                self.record_success()
                return result
            except Exception as e:
                self.record_failure()
                raise
                
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            if not self.can_execute():
                raise Exception("Circuit breaker is open")
                
            try:
                result = func(*args, **kwargs)
                self.record_success()
                return result
            except Exception as e:
                self.record_failure()
                raise
                
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper

# Example usage:
"""
@with_retry(RetryConfig(
    max_retries=3,
    base_delay=2.0,
    exceptions=(ConnectionError, TimeoutError)
))
@CircuitBreaker(
    failure_threshold=5,
    reset_timeout=60.0
)
async def scan_target(url: str):
    # Scanning logic here
    pass
"""