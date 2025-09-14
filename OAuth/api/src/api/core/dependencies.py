from fastapi_limiter.depends import RateLimiter
from src.api.config import get_settings

settings = get_settings()

def get_rate_limiter():
    return RateLimiter(
        times=settings.rate_limit.RATE_LIMIT_REQUESTS,
        seconds=settings.rate_limit.RATE_LIMIT_WINDOW,
    )