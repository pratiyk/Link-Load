from fastapi_cache import FastAPICache
from fastapi_cache.backends.redis import RedisBackend
from redis import asyncio as aioredis
from typing import Optional

from .config import settings

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

        self._initialized = True

    @property
    def redis(self):
        if not self._initialized:
            raise RuntimeError("CacheManager not initialized. Call initialize() first.")
        return self._redis

    async def close(self):
        if self._redis:
            await self._redis.close()

cache_manager = CacheManager()