import asyncio
import logging
import random
from contextlib import asynccontextmanager, nullcontext
from typing import Optional, Dict, Any

import aiohttp

from ..client.rate_limiter import RateLimiter

_LOGGER = logging.getLogger(__name__)

MAX_ATTEMPTS = 3
RETRY_STATUS_CODES = {429, 502, 503, 504}
INITIAL_BACKOFF = 1
MAX_BACKOFF = 30


@asynccontextmanager
async def _get_session(session: Optional[aiohttp.ClientSession]):
    if session is not None and not session.closed:
        yield session
    else:
        async with aiohttp.ClientSession() as new_session:
            yield new_session


async def request(
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        session: Optional[aiohttp.ClientSession] = None,
        rate_limiter: Optional[RateLimiter] = None,
        concurrency_semaphore: Optional[asyncio.Semaphore] = None,
) -> Any:
    """
    Make an HTTP request with retry, rate limiting, and concurrency control.

    Args:
        method: HTTP method (e.g., 'GET', 'POST')
        url: Full URL to call
        headers: Optional HTTP headers
        json_body: Optional JSON body for POST/PUT
        session: Optional external aiohttp ClientSession to reuse
        rate_limiter: Optional RateLimiter instance for throttling requests.
            When None, no rate limiting is applied (suitable for infrequent
            calls such as token refresh or revoke).
        concurrency_semaphore: Optional asyncio.Semaphore for limiting
            concurrent in-flight requests. When None, no concurrency
            limit is applied.
    """
    allow_retry_statuses = RETRY_STATUS_CODES

    for attempt in range(1, MAX_ATTEMPTS + 1):
        if rate_limiter is not None:
            await rate_limiter.acquire()
        retry_after_delay: Optional[float] = None

        try:
            sem = concurrency_semaphore if concurrency_semaphore is not None else nullcontext()
            async with sem:
                async with _get_session(session) as client_session:
                    async with client_session.request(
                            method=method,
                            url=url,
                            headers=headers,
                            json=json_body
                    ) as response:

                        if response.status not in allow_retry_statuses:
                            try:
                                response_body = await response.json()
                            except (aiohttp.ContentTypeError, ValueError):
                                response_body = (await response.text())[:2048]
                            status = response.status
                            if 400 <= response.status < 600:
                                raise aiohttp.ClientResponseError(
                                    request_info=response.request_info,
                                    history=response.history,
                                    status=response.status,
                                    message=str(response_body),
                                    headers=response.headers,
                                )
                            _LOGGER.debug("Response from %s. status_code: %s, body: %s", url, status, response_body)
                            return response_body

                        if attempt == MAX_ATTEMPTS:
                            response_text = (await response.text())[:2048]
                            _LOGGER.warning(f"Request failed after {MAX_ATTEMPTS} attempts. "
                                            f"Status: {response.status}, Body: {response_text}")
                            response.raise_for_status()

                        retry_after = response.headers.get("Retry-After")
                        if retry_after:
                            try:
                                retry_after_delay = float(retry_after)
                            except (ValueError, TypeError):
                                pass

                        await response.release()

        except aiohttp.ClientResponseError as e:
            if attempt == MAX_ATTEMPTS or e.status not in allow_retry_statuses:
                raise e
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            if attempt == MAX_ATTEMPTS:
                _LOGGER.warning("Request failed after %s attempts due to network error: %s", MAX_ATTEMPTS, e)
                raise e
            _LOGGER.debug("Network error on attempt %s of %s: %s. Retrying...", attempt, MAX_ATTEMPTS, e)

        # Wait before next attempt
        backoff = min(INITIAL_BACKOFF * 2 ** (attempt - 1), MAX_BACKOFF)
        if retry_after_delay is not None:
            backoff = max(backoff, retry_after_delay)
        jitter = random.uniform(0, backoff * 0.3)
        await asyncio.sleep(backoff + jitter)

    raise RuntimeError("Unexpected error in retry logic.")
