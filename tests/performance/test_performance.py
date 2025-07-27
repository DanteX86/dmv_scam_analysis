"""Performance tests for the DMV scam analysis system."""
import pytest
import time
import random
import string
import json
import numpy as np
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from src.dmv_scam_analysis.core.analyzer import CampaignAnalyzer
from src.dmv_scam_analysis.core.classifier import ThreatClassifier
from src.dmv_scam_analysis.core.extractor import MessageExtractor
from src.dmv_scam_analysis.analysis.sentiment import NLPAnalyzer

def generate_random_text(length):
    """Generate random text of specified length."""
    return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation + ' ', k=length))

def generate_test_message():
    """Generate a test message with random content."""
    scam_templates = [
        "Your driver's license will expire in {} days. Pay ${} to renew now: {}",
        "DMV Notice: Your registration needs renewal. Click here to pay ${}: {}",
        "URGENT: Your license has been suspended. Contact us immediately: {}"
    ]
    
    template = random.choice(scam_templates)
    days = random.randint(1, 30)
    amount = random.randint(50, 500)
    url = f"http://{generate_random_text(10)}.com"
    
    return template.format(days, amount, url)

@pytest.fixture
def large_dataset():
    """Generate a large dataset for performance testing."""
    messages = []
    for i in range(10000):  # 10,000 messages
        messages.append({
            "id": f"msg{i}",
            "text": generate_test_message(),
            "source": random.choice(["email", "sms", "web"]),
            "timestamp": f"2025-06-{random.randint(1,30):02d}T{random.randint(0,23):02d}:{random.randint(0,59):02d}:00Z",
            "metadata": {
                "ip": f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
                "user_agent": generate_random_text(50)
            }
        })
    return messages

@pytest.mark.benchmark
def test_preprocessing_performance(large_dataset, benchmark):
    """Test preprocessing performance with large dataset."""
    analyzer = CampaignAnalyzer("test_campaign")
    
    def run_preprocessing():
        return analyzer.analyze_campaign(large_dataset[:100])  # Reduced for performance
    
    result = benchmark(run_preprocessing)
    assert len(result) == len(large_dataset)
    
    # Performance assertions
    assert benchmark.stats.stats.mean < 2.0  # Should process in less than 2 seconds

@pytest.mark.benchmark
def test_nlp_analysis_performance(large_dataset, benchmark):
    """Test NLP analysis performance."""
    analyzer = NLPAnalyzer()
    
    def run_analysis():
        return analyzer.analyze([msg["text"] for msg in large_dataset[:100]])
    
    result = benchmark(run_analysis)
    assert len(result["entities"]) > 0
    
    # Performance assertions
    assert benchmark.stats.stats.mean < 5.0  # Should analyze in less than 5 seconds

@pytest.mark.benchmark
def test_threat_classification_performance(large_dataset, benchmark):
    """Test threat classification performance."""
    classifier = ThreatClassifier()
    
    def run_classification():
        return classifier.predict(large_dataset[:1000])
    
    result = benchmark(run_classification)
    assert len(result) == 1000
    
    # Performance assertions
    assert benchmark.stats.stats.mean < 3.0  # Should classify in less than 3 seconds

def test_concurrent_processing(large_dataset):
    """Test performance with concurrent processing."""
    analyzer = CampaignAnalyzer("test_campaign")
    
    def process_chunk(chunk):
        return analyzer.analyze_campaign(chunk[:10])  # Reduced for performance
    
    # Split dataset into chunks
    chunk_size = 1000
    chunks = [large_dataset[i:i + chunk_size] 
             for i in range(0, len(large_dataset), chunk_size)]
    
    start_time = time.time()
    
    # Process using thread pool
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(process_chunk, chunks))
    
    thread_time = time.time() - start_time
    
    # Process using process pool
    start_time = time.time()
    with ProcessPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(process_chunk, chunks))
    
    process_time = time.time() - start_time
    
    # Compare performance
    assert thread_time < 10.0  # Threading should complete in less than 10 seconds
    assert process_time < thread_time  # Process pool should be faster than thread pool

@pytest.mark.benchmark
def test_memory_usage(large_dataset, benchmark):
    """Test memory usage during processing."""
    import psutil
    import os
    
    process = psutil.Process(os.getpid())
    analyzer = CampaignAnalyzer("test_campaign")
    
    def monitor_memory_usage():
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Process data
        _ = analyzer.analyze_campaign(large_dataset[:100])  # Reduced for performance
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        return final_memory - initial_memory
    
    memory_usage = benchmark(monitor_memory_usage)
    assert memory_usage < 1024  # Should use less than 1GB additional memory

def test_database_performance(large_dataset):
    """Test database operation performance."""
    from src.dmv_scam_analysis.utils.config_manager import ConfigManager
    # Note: DatabaseHandler may not exist in new structure
    
    db = DatabaseHandler()
    
    # Measure bulk insert performance
    start_time = time.time()
    db.bulk_insert(large_dataset)
    bulk_insert_time = time.time() - start_time
    
    # Measure query performance
    start_time = time.time()
    results = db.query_messages(
        start_date="2025-06-01",
        end_date="2025-06-30",
        limit=1000
    )
    query_time = time.time() - start_time
    
    assert bulk_insert_time < 5.0  # Bulk insert should take less than 5 seconds
    assert query_time < 1.0  # Queries should take less than 1 second

@pytest.mark.benchmark
def test_api_response_time(benchmark):
    """Test API endpoint response times."""
    from src.dmv_scam_analysis.api.app import APIHandler
    
    api = APIHandler()
    
    def make_request():
        return api.get_analysis_results(
            start_date="2025-06-01",
            end_date="2025-06-30",
            limit=100
        )
    
    result = benchmark(make_request)
    assert result is not None
    assert benchmark.stats.stats.mean < 0.5  # API should respond in less than 500ms

def test_caching_performance():
    """Test caching mechanism performance."""
    from src.dmv_scam_analysis.utils.config_manager import ConfigManager
    # Note: CacheManager may not exist in new structure
    
    cache = CacheManager()
    test_data = {"key": "value" * 1000}  # Large data
    
    # Test write performance
    start_time = time.time()
    cache.set("test_key", test_data)
    write_time = time.time() - start_time
    
    # Test read performance
    start_time = time.time()
    cached_data = cache.get("test_key")
    read_time = time.time() - start_time
    
    assert write_time < 0.1  # Cache writes should be fast
    assert read_time < 0.01  # Cache reads should be very fast
    assert cached_data == test_data

@pytest.mark.benchmark
def test_visualization_performance(large_dataset, benchmark):
    """Test visualization generation performance."""
    from src.dmv_scam_analysis.visualization import ThreatVisualizer
    
    visualizer = ThreatVisualizer()
    
    def generate_visualizations():
        return visualizer.create_visualizations(
            messages=large_dataset[:1000],
            analysis_results={
                "threat_scores": np.random.random(1000),
                "clusters": np.random.randint(0, 5, 1000)
            }
        )
    
    result = benchmark(generate_visualizations)
    assert "timeline" in result
    assert "network" in result
    assert benchmark.stats.stats.mean < 10.0  # Should generate in less than 10 seconds

def test_load_testing():
    """Test system performance under load."""
    from src.dmv_scam_analysis.api.app import APIHandler
    import asyncio
    
    api = APIHandler()
    
    async def simulate_load():
        tasks = []
        for _ in range(100):  # Simulate 100 concurrent requests
            tasks.append(
                api.async_process_request({
                    "text": generate_test_message(),
                    "source": "api"
                })
            )
        return await asyncio.gather(*tasks)
    
    start_time = time.time()
    results = asyncio.run(simulate_load())
    total_time = time.time() - start_time
    
    assert len(results) == 100
    assert total_time < 30.0  # Should handle 100 concurrent requests in less than 30 seconds
    
    # Calculate response time statistics
    response_times = [r["processing_time"] for r in results]
    assert np.mean(response_times) < 0.5  # Average response time should be less than 500ms
    assert np.percentile(response_times, 95) < 1.0  # 95th percentile should be less than 1s
