import json
import time
import duckdb
from datetime import datetime, timezone
import joblib
import polars as pl
from confluent_kafka import Producer

# Kafka Setup
producer = Producer({
    'bootstrap.servers': 'localhost:19092',
    'client.id': 'security-alert-engine'
})

ALERT_TOPIC = "security.alerts"
MODEL_PATH = "src/ml/isolation_forest_net.joblib"
DELTA_NET_PATH = "data/delta/network_logs"
DELTA_SYS_PATH = "data/delta/endpoint_logs"

def delivery_report(err, msg):
    if err is not None:
        print(f"Alert Delivery Failed: {err}")

def publish_network_alerts(model):
    """Scans recent network records, scores with Isolation Forest, and emits alerts."""
    conn = duckdb.connect()
    conn.execute("INSTALL delta; LOAD delta;")
    
    # Query last 100 network records
    df = conn.execute(f"""
        SELECT uid, timestamp, src_ip, dst_ip, dst_port, orig_bytes, resp_bytes, proto
        FROM delta_scan('{DELTA_NET_PATH}')
        ORDER BY timestamp DESC
        LIMIT 100
    """).pl()

    if df.is_empty():
        return

    features_df = df.select([
        pl.col("dst_port").cast(pl.Float64),
        pl.col("orig_bytes").cast(pl.Float64),
        pl.col("resp_bytes").cast(pl.Float64),
        (pl.col("proto") == "tcp").cast(pl.Float64).alias("is_tcp"),
        (pl.col("proto") == "udp").cast(pl.Float64).alias("is_udp")
    ])

    X = features_df.to_numpy()
    preds = model.predict(X)
    scores = model.decision_function(X)

    df_anomalies = df.with_columns([
        pl.Series("is_anomaly", preds == -1),
        pl.Series("score", scores)
    ]).filter(pl.col("is_anomaly"))

    for row in df_anomalies.iter_rows(named=True):
        alert_payload = {
            "alert_id": f"ALT-NET-{row['uid']}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_type": "NETWORK_EXFILTRATION_ANOMALY",
            "severity": "HIGH" if row['orig_bytes'] > 500000 else "MEDIUM",
            "source": "IsolationForest_ML",
            "details": {
                "src_ip": row["src_ip"],
                "dst_ip": row["dst_ip"],
                "dst_port": row["dst_port"],
                "orig_bytes": row["orig_bytes"],
                "anomaly_score": round(row["score"], 4)
            }
        }
        producer.produce(
            ALERT_TOPIC,
            key=row["src_ip"],
            value=json.dumps(alert_payload),
            callback=delivery_report
        )
    producer.poll(0)

def publish_sysmon_alerts():
    """Scans endpoint logs for malicious execution strings or powershell evasion."""
    conn = duckdb.connect()
    conn.execute("INSTALL delta; LOAD delta;")

    df = conn.execute(f"""
        SELECT timestamp, host, user, process_name, parent_process, command_line
        FROM delta_scan('{DELTA_SYS_PATH}')
        WHERE command_line LIKE '%-enc%' OR command_line LIKE '%hidden%'
        ORDER BY timestamp DESC
        LIMIT 20
    """).pl()

    for row in df.iter_rows(named=True):
        alert_payload = {
            "alert_id": f"ALT-SYS-{abs(hash(str(row['timestamp']) + row['host'])) % 1000000}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_type": "SUSPICIOUS_POWERSHELL_EXECUTION",
            "severity": "CRITICAL" if "SYSTEM" in row["user"] else "HIGH",
            "source": "RuleEngine_Sysmon",
            "details": {
                "host": row["host"],
                "user": row["user"],
                "process_name": row["process_name"],
                "command_line": row["command_line"]
            }
        }
        producer.produce(
            ALERT_TOPIC,
            key=row["host"],
            value=json.dumps(alert_payload),
            callback=delivery_report
        )
    producer.poll(0)

def main():
    print("Loading Isolation Forest Model...")
    model = joblib.load(MODEL_PATH)
    print("Starting ML Security Alert Engine... Publishing to topic 'security.alerts'")

    try:
        while True:
            publish_network_alerts(model)
            publish_sysmon_alerts()
            producer.flush()
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Scanned Delta Lake & published active alerts.")
            time.sleep(10)  # Run detection cycle every 10 seconds
    except KeyboardInterrupt:
        print("Stopping alert publisher...")

if __name__ == "__main__":
    main()