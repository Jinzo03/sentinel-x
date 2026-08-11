import sys
import os
from pathlib import Path
from dotenv import load_dotenv

# 1. Add the project root (sentinel-x) to Python's path so 'src' can be found
# Since this file is at sentinel-x/src/agents/agent_service.py, go up 2 levels:
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

# 2. Load environment variables from the project root
load_dotenv(dotenv_path=project_root / '.env')

# 3. Now imports using 'src.' will work successfully
import json
import time
from datetime import datetime, timezone
from confluent_kafka import Consumer, KafkaError
from src.agents.graph import soc_agent_graph

KAFKA_BOOTSTRAP = os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'redpanda:9092')

CONSUMER_CONFIG = {
    'bootstrap.servers': KAFKA_BOOTSTRAP,
    'group.id': 'agent-soc-daemon',
    'auto.offset.reset': 'latest'
}

HISTORY_FILE = "data/agent_triage_history.json"

def load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_history(records):
    with open(HISTORY_FILE, "w") as f:
        json.dump(records, f, indent=2)

def main():
    print("[+] Starting Autonomous SOC Multi-Agent Service Daemon...")
    consumer = Consumer(CONSUMER_CONFIG)
    consumer.subscribe(["security.alerts"])

    history = load_history()

    try:
        while True:
            msg = consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    print(f"Consumer error: {msg.error()}")
                continue

            alert = json.loads(msg.value().decode('utf-8'))
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Processing Alert: {alert['alert_id']} ({alert['alert_type']})")

            initial_state = {
                "alert": alert,
                "triage_notes": "",
                "threat_intel": "",
                "remediation_plan": "",
                "messages": []
            }

            # Execute LangGraph Multi-Agent Triage
            final_state = soc_agent_graph.invoke(initial_state)

            triage_record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "alert_id": alert["alert_id"],
                "alert_type": alert["alert_type"],
                "severity": alert["severity"],
                "alert_details": alert.get("details", {}),
                "triage_notes": final_state["triage_notes"],
                "threat_intel": final_state["threat_intel"],
                "remediation_plan": final_state["remediation_plan"]
            }

            history.insert(0, triage_record)  # Keep latest at index 0
            history = history[:100]  # Retain top 100 historical triages
            save_history(history)
            
            print(f"[✓] Successfully triaged and stored record for {alert['alert_id']}")

    except KeyboardInterrupt:
        print("Stopping Agent Service...")
    finally:
        consumer.close()

if __name__ == "__main__":
    main()