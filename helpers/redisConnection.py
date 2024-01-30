_connection = None

from os import getenv
from .config import Config
from redis import asyncio as aioredis

def get():
    global _connection
    if not _connection:
        _connection = aioredis.from_url(
            Config.REDIS_PROD_CONNECTION_STRING if getenv("docker") in [1, "1"] else Config.REDIS_DEV_CONNECTION_STRING,
            decode_responses=True
        )
    return _connection