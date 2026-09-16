# Sentinel-X

**Sentinel-X** is a real-time security telemetry and autonomous triage platform. It streams synthetic network and endpoint logs through Kafka, detects anomalies with machine learning, and hands off confirmed alerts to a multi-agent LLM pipeline that performs triage, threat-intel mapping, and remediation planning — all surfaced on a live dashboard.

## Architecture

```
Producer ──▶ Redpanda (Kafka) ──▶ Consumer ──▶ Delta Lake (Polars/DuckDB)
                                                      │
                                                      ▼
                                        ML Detection (Isolation Forest, Z-Score)
                                                      │
                                                      ▼
                                          Alert Publisher ──▶ security.alerts
                                                      │
                                                      ▼
                                     LangGraph Multi-Agent SOC Service
                                    (Triage → Threat Intel → Remediation)
                                                      │
                                                      ▼
                                   FastAPI backend ──▶ Streamlit dashboard
```

## Key Components

- **Ingestion** (`src/ingestion/`) — Synthetic Zeek-style network logs and Sysmon-style process events are streamed into Redpanda topics and persisted to partitioned Delta Lake tables via a batching consumer.
- **ML Detection** (`src/ml/`) — An Isolation Forest model flags anomalous network connections (e.g. large outbound transfers to suspicious hosts); a rolling Z-score analysis flags volumetric process-execution spikes. Confirmed detections are published as structured alerts.
- **Agentic SOC Pipeline** (`src/agents/`) — A LangGraph workflow (backed by Gemini) consumes alerts and runs them through three specialized agents: **Triage** (gathers evidence from Delta Lake via DuckDB), **Threat Intelligence** (maps behavior to MITRE ATT&CK / CISA KEV via LanceDB vector search), and **Remediation** (produces a containment and detection-rule recommendation).
- **API & Dashboard** (`src/dashboard/`) — A FastAPI service exposes metrics, top-talker analytics, and agent triage history; a Streamlit dashboard visualizes live telemetry and incident feeds.

## Tech Stack

Python · FastAPI · Streamlit · Redpanda (Kafka) · Delta Lake · DuckDB · Polars · LanceDB · LangChain / LangGraph · Gemini · scikit-learn · Docker Compose

## Getting Started

### Run with Docker Compose

```bash
git clone https://github.com/Jinzo03/sentinel-x.git
cd sentinel-x
cp .env.example .env   # add GOOGLE_API_KEY
docker compose up --build
```

| Service            | URL                          |
|---------------------|-------------------------------|
| Streamlit Dashboard | http://localhost:8501         |
| FastAPI Backend     | http://localhost:8000         |
| Redpanda Console    | http://localhost:8080         |

### Run locally (development)

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 1. Start Redpanda (or point at your own Kafka cluster)
docker compose up redpanda

# 2. Seed the threat-intel vector store
python src/ingestion/seed_intel.py

# 3. Start streaming telemetry
python src/ingestion/producer.py
python src/ingestion/consumer.py

# 4. Run detection + the agent service
python src/ml/alert_publisher.py
python src/agents/agent_service.py

# 5. Launch the API and dashboard
uvicorn src.dashboard.api:app --reload
streamlit run src/dashboard/app.py
```

## Project Structure

```
sentinel-x/
├── src/
│   ├── ingestion/     # Kafka producer/consumer, Delta Lake writer, threat-intel seeding
│   ├── ml/             # Anomaly detection and alert publishing
│   ├── agents/         # LangGraph multi-agent triage pipeline
│   └── dashboard/      # FastAPI backend + Streamlit UI
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## Disclaimer

All telemetry in this project is synthetically generated for demonstration purposes. Sentinel-X does not perform real network scanning, exploitation, or intrusion — it is a simulation and portfolio project showcasing a streaming security-analytics and agentic-AI pipeline.
