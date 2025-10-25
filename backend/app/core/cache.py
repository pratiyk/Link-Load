import logging
from typing import Optional

try:
    from fastapi_cache import FastAPICache
    from fastapi_cache.backends.redis import RedisBackend
    CACHE_AVAILABLE = True
except ImportError:
    CACHE_AVAILABLE = False

try:
    from redis import asyncio as aioredis
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
            # Initialize Redis connection
            self._redis = aioredis.Redis(
                host=settings.REDIS_HOST,
                port=settings.REDIS_PORT,
                password=settings.REDIS_PASSWORD,
                db=settings.REDIS_DB,
                decode_responses=True,
                encoding="utf-8"
            )

            # Initialize FastAPI Cache
            FastAPICache.init(
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