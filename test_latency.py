import httpx
import time
import statistics

# The API endpoint
URL = "http://localhost:8000/api/ask"
PAYLOAD = {"question": "What is the Log4j vulnerability?", "source_filter": "cisa"}

latencies = []
ITERATIONS = 20 # Keep it low so your laptop doesn't melt

print(f"Running {ITERATIONS} requests to measure latency...")

for i in range(ITERATIONS):
    start_time = time.time()
    try:
        response = httpx.post(URL, json=PAYLOAD, timeout=60)
        response.raise_for_status()
    except Exception as e:
        print(f"Request {i} failed: {e}")
        continue
    
    end_time = time.time()
    latency_ms = (end_time - start_time) * 1000
    latencies.append(latency_ms)
    print(f"Request {i+1}: {latency_ms:.2f} ms")

# Calculate statistics
if latencies:
    latencies.sort()
    avg_latency = statistics.mean(latencies)
    p50 = statistics.quantiles(latencies, n=100)[49] # 50th percentile
    p95 = statistics.quantiles(latencies, n=100)[94] # 95th percentile
    p99 = latencies[-1] # With 20 requests, p99 is just the slowest one
    
    print("\n--- LATENCY REPORT ---")
    print(f"Average: {avg_latency:.2f} ms")
    print(f"p50 (Median): {p50:.2f} ms")
    print(f"p95: {p95:.2f} ms")
    print(f"p99 (Max): {p99:.2f} ms")