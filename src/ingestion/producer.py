import json
import random
import time
from datetime import datetime, timezone
from confluent_kafka import Producer

# Kafka / Redpanda Producer Configuration
PRODUCER_CONFIG = {
    'bootstrap.servers': 'localhost:19092',
    'client.id': 'telemetry-producer',
    'acks': '1'
}

producer = Producer(PRODUCER_CONFIG)

NETWORK_TOPIC = "security.network.zeek"
ENDPOINT_TOPIC = "security.endpoint.sysmon"

# Baseline IP pools & Hosts
INTERNAL_IPS = [f"10.0.1.{i}" for i in range(10, 50)]
EXTERNAL_IPS = ["8.8.8.8", "1.1.1.1", "142.250.190.46", "151.101.1.140", "185.220.101.5"]
SUSPICIOUS_IPS = ["198.51.100.45", "203.0.113.99"]
HOSTNAMES = ["WORKSTATION-01", "WORKSTATION-02", "FINANCE-PC", "DEV-SERVER-01", "DC-01"]

def delivery_report(err, msg):
    if err is not None:
        print(f"Message delivery failed: {err}")

def generate_zeek_log():
    """Generates synthetic network connection events."""
    is_anomaly = random.random() < 0.05  # 5% chance of anomalous traffic
    
    if is_anomaly:
        # Threat Pattern: High-volume DNS Tunneling or Egress Spike
        src_ip = random.choice(INTERNAL_IPS)
        dst_ip = random.choice(SUSPICIOUS_IPS)
        proto = "udp" if random.random() < 0.7 else "tcp"
        orig_bytes = random.randint(50000, 2000000)  # Unusually large outbound payload
        resp_bytes = random.randint(100, 1000)
        dst_port = 53 if proto == "udp" else 443
    else:
        # Normal web/service traffic
        src_ip = random.choice(INTERNAL_IPS)
        dst_ip = random.choice(EXTERNAL_IPS)
        proto = random.choice(["tcp", "udp"])
        dst_port = random.choice([80, 443, 53, 123])
        orig_bytes = random.randint(200, 5000)
        resp_bytes = random.randint(500, 50000)

    log = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "uid": f"C{random.randint(100000, 999999)}",
        "src_ip": src_ip,
        "src_port": random.randint(49152, 65535),
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "proto": proto,
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "conn_state": "SF"
    }
    return log

def generate_sysmon_log():
    """Generates synthetic process creation events (Sysmon Event ID 1)."""
    is_anomaly = random.random() < 0.03  # 3% chance of anomaly
    host = random.choice(HOSTNAMES)
    
    if is_anomaly:
        # Threat Pattern: Encoded PowerShell / Malicious Process Execution
        user = "NT AUTHORITY\\SYSTEM" if host == "DC-01" else f"CORP\\user_{random.randint(1, 5)}"
        process_name = "powershell.exe"
        command_line = "powershell.exe -nop -w hidden -enc aXcxY29uZmlnIC9hbGw="
        parent_process = "cmd.exe"
    else:
        # Normal process execution
        user = f"CORP\\user_{random.randint(1, 10)}"
        normal_apps = [
            ("chrome.exe", "explorer.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            ("svchost.exe", "services.exe", r"C:\Windows\System32\svchost.exe -k netsvcs"),
            ("code.exe", "explorer.exe", r"C:\Users\user\AppData\Local\Programs\Microsoft VS Code\Code.exe")
        ]
        process_name, parent_process, command_line = random.choice(normal_apps)

    log = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_id": 1,
        "host": host,
        "user": user,
        "process_name": process_name,
        "parent_process": parent_process,
        "command_line": command_line
    }
    return log

def main():
    print("Starting Telemetry Stream Producer... Press Ctrl+C to stop.")
    try:
        while True:
            # Emit Network log
            net_log = generate_zeek_log()
            producer.produce(
                NETWORK_TOPIC,
                key=net_log["src_ip"],
                value=json.dumps(net_log),
                callback=delivery_report
            )

            # Emit Endpoint log
            sys_log = generate_sysmon_log()
            producer.produce(
                ENDPOINT_TOPIC,
                key=sys_log["host"],
                value=json.dumps(sys_log),
                callback=delivery_report
            )

            producer.poll(0)
            time.sleep(0.2)  # Stream ~10 events per second

    except KeyboardInterrupt:
        print("\nStopping producer...")
    finally:
        producer.flush()

if __name__ == "__main__":
    main()