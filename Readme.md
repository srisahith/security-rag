# 🛡️ Security-RAG: Enterprise AI Threat Intelligence Platform

An advanced, locally-hosted **Hybrid Retrieval-Augmented Generation (RAG)** pipeline designed for Cyber Security Operations Centers (SOC). This platform ingests live threat intelligence, performs hybrid search (Vector + Keyword), and generates accurate, hallucination-free answers for security analysts.

Built to run entirely on consumer hardware (tested on a 16GB RAM laptop with an RTX 3050 6GB GPU) using local LLMs.

## 🚀 Key Features

*   **Hybrid Search Architecture:** Combines `pgvector` (HNSW) for semantic search with PostgreSQL `tsvector` (GIN Inverted Index) for exact keyword matching (e.g., precise CVE IDs).
*   **Multi-Source Data Ingestion:** Scrapes and ingests live data from CISA KEV, NVD, Hacker News, BleepingComputer, Krebs on Security, Cisco Talos, and Unit 42.
*   **Intelligent Chunking:** Uses Structure-Aware Chunking for NVD JSON feeds (1 CVE = 1 Chunk) and Contextual Enrichment (prepending CVE IDs and source metadata before embedding).
*   **Reranking:** Utilizes FlashRank (Cross-Encoder) to re-order retrieved chunks for maximum precision before sending to the LLM.
*   **High-Performance Caching:** Integrates Redis to cache frequent queries, reducing response times from ~6 seconds to <10 milliseconds.
*   **Asynchronous Ingestion:** Uses Celery and Redis to process massive NVD feeds in the background without blocking the API.
*   **Full Observability:** Prometheus metrics for system health (p50/p99 latency) and Langfuse for AI tracing (prompt/response debugging).
*   **Local & Private:** Runs entirely on a local GPU using Ollama (`qwen2.5:1.5b` and `nomic-embed-text`), ensuring sensitive threat data never leaves the machine.

## 🏗️ Architecture

```text
[ User / Swagger UI ]
         │
         ▼
[ FastAPI Gateway ] 
         │
         ├──> [ Redis Cache ] (Semantic Caching)
         │
         ├──> [ Celery Worker ] (Background Ingestion)
         │
         └──> [ Hybrid RAG Pipeline ]
                   │
                   ├──> [ PostgreSQL + pgvector ] (HNSW + GIN Index)
                   │
                   └──> [ Ollama (RTX 3050) ] (qwen2.5 & nomic-embed-text)