import asyncio
import time

import pytest

from dmv_scam_analysis.utils.rate_limiter import RateLimiter


@pytest.mark.security
@pytest.mark.asyncio
async def test_rate_limiter_allows_within_limit():
    rl = RateLimiter(max_requests=3, time_window=1)
    token = "t1"
    assert await rl.check_rate_limit(token) is True
    assert await rl.check_rate_limit(token) is True
    assert await rl.check_rate_limit(token) is True


@pytest.mark.security
@pytest.mark.asyncio
async def test_rate_limiter_blocks_when_exceeded_and_resets():
    rl = RateLimiter(max_requests=2, time_window=1)
    token = "t2"
    assert await rl.check_rate_limit(token) is True
    assert await rl.check_rate_limit(token) is True
    assert await rl.check_rate_limit(token) is False

    # reset only this token
    rl.reset(token)
    assert await rl.check_rate_limit(token) is True


@pytest.mark.security
@pytest.mark.asyncio
async def test_rate_limiter_wait_if_needed_waits_then_allows():
    rl = RateLimiter(max_requests=1, time_window=1)
    token = "t3"
    # consume quota
    assert await rl.check_rate_limit(token) is True

    waited, seconds = await rl.wait_if_needed(token)
    assert waited is True
    # After waiting, should be allowed again
    assert await rl.check_rate_limit(token) is True
