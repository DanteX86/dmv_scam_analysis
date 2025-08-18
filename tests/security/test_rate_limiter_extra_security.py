import pytest

from dmv_scam_analysis.utils.rate_limiter import RateLimiter


@pytest.mark.security
@pytest.mark.asyncio
async def test_rate_limiter_remaining_and_reset_time():
    rl = RateLimiter(max_requests=2, time_window=2)
    token = "t4"

    # Initially, 2 remaining, 0 reset
    rem, reset = await rl.get_remaining_requests(token)
    assert rem == 2
    assert reset == 0

    # Consume one
    assert await rl.check_rate_limit(token) is True
    rem2, reset2 = await rl.get_remaining_requests(token)
    assert rem2 == 1
    assert reset2 >= 0

    # Consume second
    assert await rl.check_rate_limit(token) is True
    rem3, reset3 = await rl.get_remaining_requests(token)
    assert rem3 == 0
    assert reset3 >= 0
