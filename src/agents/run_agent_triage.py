from dotenv import load_dotenv

# 1. Load environment variables FIRST before any local modules are imported
load_dotenv()

import json
from pathlib import Path
import sys

from confluent_kafka import Consumer

# Add project root to system path
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

# 2. Now it is safe to import from src because GOOGLE_API_KEY is already loaded
from src.agents.graph import soc_agent_graph

consumer = Consumer({
    "bootstrap.servers": "localhost:19092",
    "group.id": "agent-triage-group",
    "auto.offset.reset": "latest",
})

consumer.subscribe(["security.alerts"])


def main():
  print("Listening for alerts in 'security.alerts' topic...")
  try:
    while True:
      msg = consumer.poll(1.0)
      if msg is None:
        continue
      if msg.error():
        print(f"Consumer error: {msg.error()}")
        continue

      alert = json.loads(msg.value().decode("utf-8"))
      print("\n=======================================================")
      print(f"[+] AGENT TRIAGE TRIGGERED FOR ALERT: {alert['alert_id']}")
      print(f"Type: {alert['alert_type']} | Severity: {alert['severity']}")
      print("=======================================================")

      initial_state = {
          "alert": alert,
          "triage_notes": "",
          "threat_intel": "",
          "remediation_plan": "",
          "messages": [],
      }

      final_state = soc_agent_graph.invoke(initial_state)

      print("\n--- [1] TRIAGE ANALYSIS ---")
      print(final_state["triage_notes"])
      print("\n--- [2] THREAT INTEL MAPPING ---")
      print(final_state["threat_intel"])
      print("\n--- [3] REMEDIATION PLAN ---")
      print(final_state["remediation_plan"])

      break  # Exit after triaging one alert for testing

  except KeyboardInterrupt:
    pass
  finally:
    consumer.close()


if __name__ == "__main__":
  main()