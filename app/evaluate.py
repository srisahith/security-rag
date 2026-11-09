import httpx
import time
import re

# Configuration
API_URL = "http://localhost:8000/api/ask"

# 🎯 The Golden Dataset
TEST_CASES = [
    {
        "question": "What is the CVE-2024-22087",
        "source_filter": None,       # 🚨 None, not "null"
        "days_back": None,           # 🚨 None, not "null"
        "ground_truth": "Description: route in main.c in Pico HTTP Server in C through f3b69a6 has an sprintf stack-based buffer overflow via a long URI, leading to remote code execution."
    },
    {
        "question": "Iris Ohyama data cloud breach exposes info of 7.7 million customers",
        "source_filter": None,
        "days_back": None,
        "ground_truth": "Japanese manufacturer Iris Ohyama, the operator of the Iris Plaza shopping platform, disclosed that personal information belonging to about 7.7 million people may have been exposed after unauthorized access to a third-party cloud service the company used. [...]"
    }
]

def run_evaluation():
    print("🧪 Starting Automated RAG Evaluation...\n")
    
    total_latency = 0
    total_score = 0
    hits = 0

    for i, test in enumerate(TEST_CASES, 1):
        print(f"Test {i}: {test['question']} (Filter: {test['source_filter'] or 'All Sources'})")
        
        # 🚨 Fixed Payload (Includes days_back)
        payload = {
            "question": test["question"],
            "source_filter": test["source_filter"],
            "days_back": test["days_back"]
        }
        
        start_time = time.time()
        
        try:
            response = httpx.post(API_URL, json=payload, timeout=120) # Increased timeout for LLM
            
            if response.status_code == 422:
                print(f"  ❌ 422 Validation Error: {response.json()}")
                continue
                
            response.raise_for_status()
            data = response.json()
            
        except Exception as e:
            print(f"  ❌ API Connection Error: {e}\n")
            continue
            
        latency_ms = (time.time() - start_time) * 1000
        total_latency += latency_ms

        context_snippet = str(data.get("context_snippet", "")).lower()
        ai_answer = str(data.get("ai_answer", "")).lower()
        
        # 🚨 Dynamic Hit Detection: Extract CVE ID from question if no keyword provided
        cve_match = re.search(r'CVE-\d{4}-\d{4,7}', test["question"], re.IGNORECASE)
        
        if cve_match:
            keyword = cve_match.group(0).lower() # Look for the CVE ID
        else:
            # If no CVE, pick a random word from the question (e.g., "Iris", "Ohyama")
            keyword = test["question"].split()[1].lower() 
        
        hit = (keyword in ai_answer) or (keyword in context_snippet)
        
        if hit:
            print(f"  🔍 Retrieval: ✅ HIT (Found '{keyword}')")
            hits += 1
            judge_score = 5
        else:
            print(f"  🔍 Retrieval: ❌ MISS (Looked for '{keyword}')")
            judge_score = 2
            
        total_score += judge_score
        
        print(f"  📄 Context: {context_snippet[:150]}...")
        print(f"  🤖 AI Answer: {ai_answer[:150]}...")
        print(f"  ⚖️ Judge Score: {judge_score}/5")
        print(f"  ⏱️ Latency: {latency_ms:.2f} ms\n")

    # Final Report
    print("========================================")
    print("📊 EVALUATION REPORT")
    print("========================================")
    print(f"Total Tests: {len(TEST_CASES)}")
    print(f"Retrieval Hit Rate: {(hits/len(TEST_CASES))*100:.1f}%")
    print(f"Average Accuracy Score: {total_score/len(TEST_CASES):.2f} / 5.0")
    print(f"Average Latency: {total_latency/len(TEST_CASES):.2f} ms")
    print("========================================")

if __name__ == "__main__":
    run_evaluation()
    # Flush Langfuse events
    try:
        from langfuse import Langfuse
        langfuse = Langfuse()
        langfuse.flush()
        print("✅ Langfuse events flushed.")
    except Exception:
        pass