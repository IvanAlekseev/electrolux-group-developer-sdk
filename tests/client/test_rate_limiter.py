import asyncio
import time

import pytest

from electrolux_group_developer_sdk.client.rate_limiter import RateLimiter


@pytest.mark.asyncio
async def test_acquire_does_not_block_other_coroutines():
    """Verify that acquire() releases the lock while sleeping, allowing
    other coroutines to proceed through their own acquire() calls."""
    limiter = RateLimiter(max_calls=1, period=0.5)

    # First acquire succeeds immediately and fills the single slot
    await limiter.acquire()

    second_acquired = asyncio.Event()
    lock_was_free_during_sleep = False

    async def second_caller():
        nonlocal lock_was_free_during_sleep
        # This will need to sleep because the slot is full.
        # If the lock is released during sleep, we can probe it.
        await limiter.acquire()
        second_acquired.set()

    async def lock_prober():
        nonlocal lock_was_free_during_sleep
        # Give second_caller a moment to enter acquire() and start sleeping
        await asyncio.sleep(0.05)
        # Try to inspect the internal lock — if the fix is correct,
        # the lock should be released while second_caller sleeps
        if not limiter._lock.locked():
            lock_was_free_during_sleep = True

    task_second = asyncio.create_task(second_caller())
    task_prober = asyncio.create_task(lock_prober())

    await asyncio.wait_for(
        asyncio.gather(task_second, task_prober),
        timeout=2.0,
    )

    assert second_acquired.is_set()
    assert lock_was_free_during_sleep, (
        "Lock should be released during sleep in acquire()"
    )


@pytest.mark.asyncio
async def test_acquire_respects_rate_limit():
    """Verify that acquire() still enforces the rate limit correctly."""
    limiter = RateLimiter(max_calls=2, period=0.5)

    # Fill both slots
    await limiter.acquire()
    await limiter.acquire()

    # Third acquire should wait approximately 0.5s
    start = time.monotonic()
    await asyncio.wait_for(limiter.acquire(), timeout=2.0)
    elapsed = time.monotonic() - start

    assert elapsed >= 0.4, f"Expected ~0.5s wait, got {elapsed:.3f}s"


@pytest.mark.asyncio
async def test_concurrent_acquires_do_not_deadlock():
    """Verify that multiple concurrent acquire() calls complete without deadlock."""
    limiter = RateLimiter(max_calls=3, period=0.3)

    results = []

    async def caller(idx):
        await limiter.acquire()
        results.append(idx)

    # Launch 6 concurrent callers (2x the max_calls)
    tasks = [asyncio.create_task(caller(i)) for i in range(6)]
    await asyncio.wait_for(asyncio.gather(*tasks), timeout=3.0)

    assert sorted(results) == list(range(6))
