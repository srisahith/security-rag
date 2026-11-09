import os
from celery import Celery

redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
celery_app = Celery("aegis_tasks", broker=redis_url, backend=redis_url)

# @celery_app.task
# def trigger_dast_scan(target_url: str):
#     # We import here to avoid circular import issues
#     from app.agents.dast_agent import run_ai_dast_scan
#     return run_ai_dast_scan(target_url)

# @celery_app.task
# def trigger_iris_lockdown(ip_address: str, payload: str):
#     from app.agents.iris_agent import analyze_and_block_identity
#     return analyze_and_block_identity(ip_address, payload)

import subprocess
from app.workers import celery_app # (Assuming celery_app is already defined here)

@celery_app.task
def process_data_lake_task():
    """Runs the heavy ingestion pipeline in the background."""
    print("[CELERY] Starting Data Lake Ingestion...")
    try:
        # Run the script as a subprocess so it doesn't block the worker
        result = subprocess.run(
            ["python", "-m", "app.process_lake"], 
            capture_output=True, 
            text=True
        )
        print(f"[CELERY] Ingestion Output: {result.stdout[-500:]}") # Print last 500 chars
        if result.stderr:
            print(f"[CELERY] Ingestion Error: {result.stderr}")
        return "Ingestion Complete"
    except Exception as e:
        return f"Ingestion Failed: {e}"