import logging
from typing import Optional


try:
    from fastapi_cache2 import FastApiCache
    from fastapi_cache2.backends.redis import RedisBackend
    CACHE_AVAILABLE = True
except ImportError:
    CACHE_AVAILABLE = False

try:
    import redis.asyncio as redis_asyncio
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

from .config import settings

logger = logging.getLogger(__name__)

class CacheManager:
    _instance: Optional['CacheManager'] = None
    _redis = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(CacheManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    async def initialize(self):
        if self._initialized:
            return

        if not CACHE_AVAILABLE or not REDIS_AVAILABLE:
            logger.warning(
                "Cache dependencies not available (fastapi-cache or redis-py missing). "
                "Running without cache support."
            )
            self._initialized = True
            return


        try:
            # Create redis.asyncio connection
            redis_url = f"redis://{settings.REDIS_HOST}:{settings.REDIS_PORT}/{settings.REDIS_DB}"
            self._redis = redis_asyncio.from_url(redis_url, decode_responses=True)
            FastApiCache.init(
                RedisBackend(self._redis),
                prefix="linkload_cache:",
                expire=settings.CACHE_EXPIRE_IN_SECONDS
            )
            logger.info("Cache initialized successfully")
        except Exception as e:
            logger.warning(f"Failed to initialize cache: {e}. Running without cache support.")
            self._redis = None

        self._initialized = True

    @property
    def redis(self):
        if not self._initialized:
            raise RuntimeError("CacheManager not initialized. Call initialize() first.")
        return self._redis


    async def close(self):
        if self._redis:
            try:
                await self._redis.close()
                logger.info("Cache connections closed")
            except Exception as e:
                logger.warning(f"Error closing cache: {e}")

cache_manager = CacheManager()