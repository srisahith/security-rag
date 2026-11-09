import os
import redis
from datetime import datetime

redis_client = redis.Redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379/0"))

def analyze_and_block_identity(ip_address: str, attack_payload: str):
    print(f"[IRIS] 🚨 Threat detected from {ip_address}. Payload: {attack_payload}")
    
    # DSA: Sliding Window for rate limiting
    current_time = datetime.now().timestamp()
    redis_client.rpush(f"attacks:{ip_address}", current_time)
    redis_client.ltrim(f"attacks:{ip_address}", -10, -1) # Keep last 10
    
    attack_count = redis_client.llen(f"attacks:{ip_address}")
    print(f"[IRIS] IP has {attack_count} recent violations.")

    # Remediation Action
    if attack_count >= 1:
        print(f"[IRIS] 🛑 ACTION: Adding {ip_address} to the Redis Blocklist.")
        redis_client.sadd("blocked_ips", ip_address)
        return True
    return False

def is_ip_blocked(ip_address: str) -> bool:
    return redis_client.sismember("blocked_ips", ip_address)