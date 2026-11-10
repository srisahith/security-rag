# 🛡️ Aegis-Sentinel: Multi-Agent MCP Threat Intelligence Platform

An advanced, locally-hosted **Multi-Agent RAG Platform** designed for Cyber Security Operations Centers (SOC). Built with **LangGraph Orchestration**, **Model Context Protocol (MCP)**, and **Hybrid Search (pgvector)**, this system triages user intent, retrieves threat intel via a decoupled MCP Server, and generates actionable remediation plans using local LLMs.

Built to run entirely on consumer hardware (tested on a 16GB RAM laptop with an RTX 3050 6GB GPU).

## 🚀 Key Features

*   **Loose-Coupled MCP Architecture:** The database is exposed as a standardized MCP Tool, decoupling the AI agents from the SQL layer.
*   **LangGraph Orchestration:** A state machine (Triage → Threat Intel → Remediation → Finalize) manages the agent workflow with deterministic guardrails.
*   **Hybrid Search:** Combines `pgvector` (HNSW) for semantic search with PostgreSQL `tsvector` (GIN) for exact CVE/VDB matching.
*   **Multi-Source Ingestion:** Scrapes live data from CISA, NVD, Hacker News, BleepingComputer, Krebs, Cisco Talos, and Unit 42.
*   **Intelligent Chunking:** Structure-aware chunking with contextual enrichment (prepending CVE IDs before embedding) and recursive fallbacks.
*   **Reranking:** Utilizes FlashRank to re-order retrieved chunks for maximum precision.
*   **High-Performance Caching:** Redis caches frequent queries, reducing response times from ~6s to <10ms.
*   **Full Observability:** Prometheus (system metrics) and Langfuse (AI tracing/prompt debugging).
*   **Secure by Design:** JWT Authentication, Rate Limiting (SlowAPI), and Deterministic Guardrails.

## 🏗️ Architecture Diagram

```text
┌─────────────────────────────────────────────────────────────────────┐
│                        WINDOWS HOST (GPU)                           │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                    Ollama (RTX 3050 6GB)                      │  │
│  │   ┌─────────────────────┐    ┌────────────────────────────┐   │  │
│  │   │ qwen2.5:1.5b        │    │ nomic-embed-text           │   │  │
│  │   │ (Reasoning/Agents)  │    │ (Embeddings for RAG)       │   │  │
│  │   └─────────────────────┘    └────────────────────────────┘   │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                              ▲
                              │ HTTP (host.docker.internal:11434)
                              │
┌─────────────────────────────┼───────────────────────────────────────┐
│                    DOCKER NETWORK (WSL2)                            │
│                                                                     │
│  ┌──────────────┐     ┌──────────────────────────────────────────┐  │
│  │  Streamlit   │────▶│           FastAPI Gateway                │  │
│  │  UI (8501)   │     │  (JWT Auth, Rate Limit, Prometheus)      │  │
│  └──────────────┘     └──────────────────┬───────────────────────┘  │
│                                          │                          │
│                                          ▼                          │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │              LangGraph Orchestrator (State Machine)           │  │
│  │   ┌──────────┐    ┌──────────────┐    ┌──────────────────┐   │  │
│  │   │  Triage  │───▶│ Threat Intel │───▶│   Remediation    │   │  │
│  │   │  Agent   │    │   (MCP)      │    │     Agent        │   │  │
│  │   └──────────┘    └──────┬───────┘    └──────────────────┘   │  │
│  │        │                 │                    │              │  │
│  │        ▼                 ▼                    ▼              │  │
│  │   Guardrails       MCP Client           qwen2.5 LLM         │  │
│  └───────────────────────────┼──────────────────────────────────┘  │
│                              │ stdio (spawns subprocess)            │
│                              ▼                                      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │              MCP Server (Standalone Process)                 │  │
│  │   Tool: search_cve(question) → SQL + Embedding + HNSW        │  │
│  └───────────────────────────┬──────────────────────────────────┘  │
│                              │                                      │
│         ┌────────────────────┼────────────────────┐                 │
│         ▼                    ▼                    ▼                 │
│  ┌────────────┐      ┌────────────┐      ┌────────────┐             │
│  │ PostgreSQL │      │   Redis    │      │  Langfuse  │             │
│  │ + pgvector │      │  (Cache +  │      │ (AI Tracing│             │
│  │ (HNSW+GIN) │      │  Pub/Sub)  │      │  & Evals)  │             │
│  └────────────┘      └────────────┘      └────────────┘             │
│                                                                     │
│  ┌────────────┐      ┌────────────┐      ┌────────────┐             │
│  │ Prometheus │      │  Grafana   │      │   Celery   │             │
│  │ (Metrics)  │      │ (Dashboard)│      │  (Worker)  │             │
│  └────────────┘      └────────────┘      └────────────┘             │
└─────────────────────────────────────────────────────────────────────┘