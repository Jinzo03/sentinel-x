import os

import streamlit as st
import requests
import pandas as pd
import plotly.express as px

st.set_page_config(
    page_title="Sentinel-X SOC Control Plane",
    layout="wide"
)


API_URL = os.getenv("API_URL", "http://api:8000")

st.title(" Sentinel-X: Autonomous Security Operations Center")
st.markdown("Real-time Infrastructure Telemetry, Behavioral Anomaly Detection & Multi-Agent Triage")

# Fetch Metrics
try:
    metrics = requests.get(f"{API_URL}/api/metrics").json()
    top_talkers = requests.get(f"{API_URL}/api/network/top-talkers").json()
    agent_history = requests.get(f"{API_URL}/api/agent/history").json()
except Exception as e:
    st.error(f"Cannot connect to FastAPI backend on {API_URL}. Ensure api.py is running! Error: {e}")
    st.stop()

# Top Metric Cards
col1, col2, col3 = st.columns(3)
col1.metric("Ingested Network Events", f"{metrics['total_network_events']:,}")
col2.metric("Ingested Endpoint Events", f"{metrics['total_endpoint_events']:,}")
col3.metric("Triaged Agent Incident Count", len(agent_history))

st.divider()

# Layout: Left side Telemetry Graphs, Right side Agent Operations
left_col, right_col = st.columns([1, 1])

with left_col:
    st.subheader("High-Volume Outbound Egress Telemetry")
    if top_talkers:
        df_talkers = pd.DataFrame(top_talkers)
        fig = px.bar(
            df_talkers, 
            x="src_ip", 
            y="total_bytes", 
            color="conn_count",
            labels={"total_bytes": "Total Bytes Out", "src_ip": "Source IP"},
            title="Top Outbound Egress Bandwidth by Host"
        )
        st.plotly_chart(fig, use_container_width=True)

with right_col:
    st.subheader("Live Autonomous Agent Incident Feed")
    if not agent_history:
        st.info("No agent triages recorded yet. Start `agent_service.py` to stream live incidents.")
    else:
        for idx, item in enumerate(agent_history[:5]):
            sev_color = "🔴" if item["severity"] in ["HIGH", "CRITICAL"] else "🟡"
            with st.expander(f"{sev_color} [{item['severity']}] {item['alert_id']} - {item['alert_type']}"):
                st.caption(f"**Timestamp**: {item['timestamp']}")
                st.markdown("#### Triage Analysis")
                st.write(item["triage_notes"])
                
                st.markdown("#### MITRE ATT&CK & Threat Intel")
                st.write(item["threat_intel"])
                
                st.markdown("#### Recommended Remediation Plan")
                st.info(item["remediation_plan"])