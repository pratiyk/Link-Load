from contextlib import contextmanager
from typing import Generator, Optional
from sqlalchemy.orm import Session
from sqlalchemy import text
from loguru import logger
import functools
from app.database import get_db

class TransactionManager:
    def __init__(self):
        self._db: Optional[Session] = None

    @contextmanager
    def transaction(self) -> Generator[Session, None, None]:
        """Context manager for database transactions"""
        if self._db is not None:
            # Reuse existing transaction
            yield self._db
            return

        db = next(get_db())
        self._db = db
        try:
            yield db
            db.commit()
        except Exception as e:
            logger.error(f"Transaction failed: {str(e)}")
            db.rollback()
            raise
        finally:
            self._db = None
            db.close()

def transactional(func):
    """Decorator for automatic transaction handling"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        with transaction_manager.transaction() as session:
            return func(*args, session=session, **kwargs)
    return wrapper

class BatchOperation:
    """Helper for batched database operations"""
    def __init__(self, session: Session, batch_size: int = 1000):
        self.session = session
        self.batch_size = batch_size
        self.count = 0
        
    def add(self, obj):
        """Add object to batch"""
        self.session.add(obj)
        self.count += 1
        
        if self.count >= self.batch_size:
            self.flush()
            
    def flush(self):
        """Flush current batch"""
        if self.count > 0:
            try:
                self.session.flush()
                self.count = 0
            except Exception as e:
                self.session.rollback()
                raise Exception(f"Batch operation failed: {str(e)}")
                
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self.flush()
        else:
            self.session.rollback()
            
class LockManager:
    """Helper for managing database locks"""
    def __init__(self, session: Session):
        self.session = session
        
    def acquire_lock(self, lock_key: str, timeout: int = 30) -> bool:
        """Acquire a named lock"""
        try:
            result = self.session.execute(
                text("SELECT pg_try_advisory_lock(:lock_key::bigint)"),
                {"lock_key": hash(lock_key)}
            ).scalar()
            return bool(result)
        except Exception as e:
            logger.error(f"Failed to acquire lock {lock_key}: {str(e)}")
            return False
            
    def release_lock(self, lock_key: str) -> bool:
        """Release a named lock"""
        try:
            result = self.session.execute(
                text("SELECT pg_advisory_unlock(:lock_key::bigint)"),
                {"lock_key": hash(lock_key)}
            ).scalar()
            return bool(result)
        except Exception as e:
            logger.error(f"Failed to release lock {lock_key}: {str(e)}")
            return False
            
    @contextmanager
    def lock(self, lock_key: str, timeout: int = 30):
        """Context manager for lock handling"""
        acquired = False
        try:
            acquired = self.acquire_lock(lock_key, timeout)
            if not acquired:
                raise Exception(f"Failed to acquire lock: {lock_key}")
            yield
        finally:
            if acquired:
                self.release_lock(lock_key)

# Global instances
transaction_manager = TransactionManager()

# Example usage:
"""
@transactional
def create_scan(scan_data: dict, session: Session):
    # Database operations here
    pass

# Or with explicit transaction:
with transaction_manager.transaction() as session:
    # Batch operation
    with BatchOperation(session, batch_size=1000) as batch:
        for item in items:
            batch.add(item)
            
    # With locking
    lock_manager = LockManager(session)
    with lock_manager.lock("scan_123"):
        # Exclusive operation here
        pass
"""