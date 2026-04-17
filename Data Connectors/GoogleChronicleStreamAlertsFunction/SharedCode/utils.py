"""Utility helpers: exponential-backoff retry."""
import random
import time
from functools import wraps
from typing import Callable, Iterable, Type

from . import consts
from .logger import applogger


def retry_on_exception(
    exceptions: Iterable[Type[BaseException]],
    max_retries: int = consts.MAX_RETRIES,
    base_delay: float = consts.RETRY_BASE_DELAY_SECONDS,
) -> Callable:
    """Retry the wrapped call with exponential backoff + jitter."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except tuple(exceptions) as exc:
                    last_exc = exc
                    if attempt == max_retries:
                        break
                    delay = base_delay * (2 ** attempt) + random.uniform(0, 0.5)
                    applogger.warning(
                        "%s: %s failed (attempt %d/%d): %s; retrying in %.2fs",
                        consts.LOG_PREFIX,
                        func.__name__,
                        attempt + 1,
                        max_retries + 1,
                        exc,
                        delay,
                    )
                    time.sleep(delay)
            raise last_exc  # type: ignore[misc]
        return wrapper
    return decorator
