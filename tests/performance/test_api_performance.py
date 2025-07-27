"""Performance tests for the API endpoints."""
import pytest
import asyncio
from dmv_scam_analysis.api.app import app
from fastapi.testclient import TestClient
from dmv_scam_analysis.utils.test_helpers import create_test_dataset
import time
import statistics

@pytest.fixture
def test_client():
    """Create test client."""
    return TestClient(app)

@pytest.fixture
def test_token():
    """Create test token."""
    return "test_performance_token"

@pytest.fixture
def test_messages():
    """Create test messages."""
    df = create_test_dataset(size=1000, scam_ratio=0.5)
    return df.to_dict(orient="records")

def test_analyze_endpoint_response_time(test_client, test_token, test_messages, benchmark):
    """Test response time of analyze endpoint."""
    headers = {"Authorization": f"Bearer {test_token}"}
    
    def run_analyze():
        response = test_client.post(
            "/analyze",
            headers=headers,
            json=test_messages[0]
        )
        assert response.status_code == 200
        return response
    
    # Run benchmark
    result = benchmark(run_analyze)
    
    # Verify performance
    assert result.stats.mean < 0.1  # Mean response time under 100ms

def test_analyze_endpoint_concurrent(test_client, test_token, test_messages):
    """Test concurrent requests to analyze endpoint."""
    headers = {"Authorization": f"Bearer {test_token}"}
    
    async def make_request():
        start_time = time.time()
        response = test_client.post(
            "/analyze",
            headers=headers,
            json=test_messages[0]
        )
        end_time = time.time()
        return response.status_code, end_time - start_time
    
    # Make 50 concurrent requests
    num_requests = 50
    loop = asyncio.get_event_loop()
    tasks = [make_request() for _ in range(num_requests)]
    results = loop.run_until_complete(asyncio.gather(*tasks))
    
    # Analyze results
    status_codes, response_times = zip(*results)
    
    # All requests should succeed
    assert all(code == 200 for code in status_codes)
    
    # Calculate statistics
    mean_time = statistics.mean(response_times)
    p95_time = statistics.quantiles(response_times, n=20)[18]  # 95th percentile
    
    # Performance assertions
    assert mean_time < 0.1  # Mean under 100ms
    assert p95_time < 0.2  # 95th percentile under 200ms

def test_stats_endpoint_response_time(test_client, test_token, benchmark):
    """Test response time of stats endpoint."""
    headers = {"Authorization": f"Bearer {test_token}"}
    
    def run_stats():
        response = test_client.get(
            "/stats",
            headers=headers,
            params={
                "start_date": "2025-06-20T00:00:00Z",
                "end_date": "2025-06-27T23:59:59Z"
            }
        )
        assert response.status_code == 200
        return response
    
    # Run benchmark
    result = benchmark(run_stats)
    
    # Verify performance
    assert result.stats.mean < 0.05  # Mean response time under 50ms

def test_memory_usage(test_client, test_token, test_messages):
    """Test memory usage during heavy load."""
    import psutil
    import os
    
    process = psutil.Process(os.getpid())
    headers = {"Authorization": f"Bearer {test_token}"}
    
    # Measure initial memory
    initial_memory = process.memory_info().rss
    
    # Make 1000 sequential requests
    for i in range(1000):
        response = test_client.post(
            "/analyze",
            headers=headers,
            json=test_messages[i % len(test_messages)]
        )
        assert response.status_code == 200
    
    # Measure final memory
    final_memory = process.memory_info().rss
    memory_increase = final_memory - initial_memory
    
    # Memory increase should be reasonable
    assert memory_increase < 100 * 1024 * 1024  # Less than 100MB increase

def test_cpu_usage(test_client, test_token, test_messages):
    """Test CPU usage during heavy load."""
    import psutil
    import os
    
    process = psutil.Process(os.getpid())
    headers = {"Authorization": f"Bearer {test_token}"}
    
    # Monitor CPU usage
    cpu_percents = []
    
    # Make requests and measure CPU
    for i in range(100):
        start_time = time.time()
        
        response = test_client.post(
            "/analyze",
            headers=headers,
            json=test_messages[i % len(test_messages)]
        )
        assert response.status_code == 200
        
        # Measure CPU usage
        cpu_percent = process.cpu_percent()
        cpu_percents.append(cpu_percent)
        
        # Wait a bit to get accurate CPU measurement
        time.sleep(max(0, 0.1 - (time.time() - start_time)))
    
    # Calculate statistics
    avg_cpu = statistics.mean(cpu_percents)
    max_cpu = max(cpu_percents)
    
    # CPU usage should be reasonable
    assert avg_cpu < 50  # Average CPU under 50%
    assert max_cpu < 80  # Max CPU under 80%

def test_rate_limiter_performance(test_client, test_token, test_messages, benchmark):
    """Test rate limiter performance."""
    headers = {"Authorization": f"Bearer {test_token}"}
    
    def check_rate_limit():
        response = test_client.post(
            "/analyze",
            headers=headers,
            json=test_messages[0]
        )
        return response.status_code
    
    # Run benchmark
    result = benchmark(check_rate_limit)
    
    # Rate limiting should add minimal overhead
    assert result.stats.mean < 0.001  # Under 1ms overhead

def test_database_performance(test_client, test_token, benchmark):
    """Test database operation performance."""
    headers = {"Authorization": f"Bearer {test_token}"}
    
    def query_stats():
        response = test_client.get(
            "/stats",
            headers=headers,
            params={
                "start_date": "2025-06-20T00:00:00Z",
                "end_date": "2025-06-27T23:59:59Z"
            }
        )
        return response.json()
    
    # Run benchmark
    result = benchmark(query_stats)
    
    # Database queries should be fast
    assert result.stats.mean < 0.05  # Under 50ms

def test_model_inference_time(test_client, test_token, test_messages, benchmark):
    """Test model inference time."""
    headers = {"Authorization": f"Bearer {test_token}"}
    
    def run_inference():
        response = test_client.post(
            "/analyze",
            headers=headers,
            json=test_messages[0]
        )
        return response.json()["threat_score"]
    
    # Run benchmark
    result = benchmark(run_inference)
    
    # Model inference should be fast
    assert result.stats.mean < 0.1  # Under 100ms
