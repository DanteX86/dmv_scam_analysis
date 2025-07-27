"""Unit tests for rate limiter."""
import pytest
import time
import asyncio
from dmv_scam_analysis.utils.rate_limiter import RateLimiter

@pytest.fixture
def rate_limiter():
    """Create a rate limiter instance for testing."""
    return RateLimiter(max_requests=3, time_window=1)

@pytest.mark.asyncio
async def test_rate_limiter_basic(rate_limiter):
    """Test basic rate limiting functionality."""
    # First 3 requests should succeed
    assert await rate_limiter.check_rate_limit("test_token") is True
    assert await rate_limiter.check_rate_limit("test_token") is True
    assert await rate_limiter.check_rate_limit("test_token") is True
    
    # Fourth request should fail
    assert await rate_limiter.check_rate_limit("test_token") is False

@pytest.mark.asyncio
async def test_rate_limiter_window_reset(rate_limiter):
    """Test rate limit window reset."""
    # Use up the limit
    assert await rate_limiter.check_rate_limit("test_token") is True
    assert await rate_limiter.check_rate_limit("test_token") is True
    assert await rate_limiter.check_rate_limit("test_token") is True
    
    # Wait for window to reset
    await asyncio.sleep(1)
    
    # Should be able to make requests again
    assert await rate_limiter.check_rate_limit("test_token") is True

@pytest.mark.asyncio
async def test_multiple_tokens(rate_limiter):
    """Test rate limiting for multiple tokens."""
    # First token
    assert await rate_limiter.check_rate_limit("token1") is True
    assert await rate_limiter.check_rate_limit("token1") is True
    assert await rate_limiter.check_rate_limit("token1") is True
    assert await rate_limiter.check_rate_limit("token1") is False
    
    # Second token should have its own limit
    assert await rate_limiter.check_rate_limit("token2") is True
    assert await rate_limiter.check_rate_limit("token2") is True
    assert await rate_limiter.check_rate_limit("token2") is True

@pytest.mark.asyncio
async def test_get_remaining_requests(rate_limiter):
    """Test getting remaining request count."""
    # Fresh token should have max requests
    remaining, reset_time = await rate_limiter.get_remaining_requests("test_token")
    assert remaining == 3
    assert reset_time == 0
    
    # Use one request
    await rate_limiter.check_rate_limit("test_token")
    remaining, reset_time = await rate_limiter.get_remaining_requests("test_token")
    assert remaining == 2
    assert reset_time > 0

@pytest.mark.asyncio
async def test_wait_if_needed(rate_limiter):
    """Test waiting for rate limit reset."""
    # Use up the limit
    for _ in range(3):
        assert await rate_limiter.check_rate_limit("test_token") is True
    
    # Try to wait for reset
    start_time = time.time()
    waited, wait_time = await rate_limiter.wait_if_needed("test_token")
    end_time = time.time()
    
    assert waited is True
    assert wait_time > 0
    assert end_time - start_time >= wait_time

@pytest.mark.asyncio
async def test_reset(rate_limiter):
    """Test resetting rate limiter."""
    # Use some requests
    await rate_limiter.check_rate_limit("token1")
    await rate_limiter.check_rate_limit("token2")
    
    # Reset specific token
    rate_limiter.reset("token1")
    remaining1, _ = await rate_limiter.get_remaining_requests("token1")
    remaining2, _ = await rate_limiter.get_remaining_requests("token2")
    assert remaining1 == 3  # Reset
    assert remaining2 == 2  # Not reset
    
    # Reset all
    rate_limiter.reset()
    remaining1, _ = await rate_limiter.get_remaining_requests("token1")
    remaining2, _ = await rate_limiter.get_remaining_requests("token2")
    assert remaining1 == 3
    assert remaining2 == 3

@pytest.mark.asyncio
async def test_concurrent_requests():
    """Test rate limiter under concurrent load."""
    limiter = RateLimiter(max_requests=5, time_window=1)
    token = "test_token"
    
    async def make_request():
        return await limiter.check_rate_limit(token)
    
    # Make 10 concurrent requests
    tasks = [make_request() for _ in range(10)]
    results = await asyncio.gather(*tasks)
    
    # Should have 5 successful and 5 failed requests
    assert sum(results) == 5
    assert len(results) - sum(results) == 5
