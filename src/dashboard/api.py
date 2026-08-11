import json
import os
import duckdb
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Sentinel-X Telemetry & Agent API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DELTA_NET_PATH = "data/delta/network_logs"
DELTA_SYS_PATH = "data/delta/endpoint_logs"
HISTORY_FILE = "data/agent_triage_history.json"

@app.get("/api/metrics")
def get_system_metrics():
    """Returns top-level metric counters from Delta Lake."""
    conn = duckdb.connect()
    conn.execute("INSTALL delta; LOAD delta;")
    
    total_net = conn.execute(f"SELECT COUNT(*) FROM delta_scan('{DELTA_NET_PATH}')").fetchone()[0]
    total_sys = conn.execute(f"SELECT COUNT(*) FROM delta_scan('{DELTA_SYS_PATH}')").fetchone()[0]
    
    return {
        "total_network_events": total_net,
        "total_endpoint_events": total_sys,
        "status": "HEALTHY"
    }

@app.get("/api/network/top-talkers")
def get_top_talkers():
    """Queries top bandwidth-consuming internal hosts."""
    conn = duckdb.connect()
    conn.execute("INSTALL delta; LOAD delta;")
    
    query = f"""
        SELECT src_ip, COUNT(*) as conn_count, SUM(orig_bytes) as total_bytes
        FROM delta_scan('{DELTA_NET_PATH}')
        GROUP BY src_ip
        ORDER BY total_bytes DESC
        LIMIT 5
    """
    df = conn.execute(query).df()
    return df.to_dict(orient="records")

@app.get("/api/agent/history")
def get_agent_history():
    """Returns the latest agent triage history records."""
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return []
    return []

@app.get("/health")
def get_health():
    return {"status": "healthy"}