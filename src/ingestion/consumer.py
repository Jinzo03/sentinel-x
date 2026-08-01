import json
import time
from datetime import datetime
from confluent_kafka import Consumer, KafkaError
import polars as pl

CONSUMER_CONFIG = {
    'bootstrap.servers': 'localhost:19092',
    'group.id': 'delta-lake-ingestor',
    'auto.offset.reset': 'earliest',
    'enable.auto.commit': False
}

consumer = Consumer(CONSUMER_CONFIG)
consumer.subscribe(["security.network.zeek", "security.endpoint.sysmon"])

NETWORK_DELTA_PATH = "data/delta/network_logs"
ENDPOINT_DELTA_PATH = "data/delta/endpoint_logs"

BATCH_SIZE = 50  # Flush to disk every 50 records per batch
BATCH_TIMEOUT = 5.0  # Or flush every 5 seconds

def write_batch_to_delta(records: list):
    """Processes a raw message batch and writes to Delta Lake via Polars."""
    if not records:
        return

    net_records = [r for r in records if r["_topic"] == "security.network.zeek"]
    sys_records = [r for r in records if r["_topic"] == "security.endpoint.sysmon"]

    # Process Network Logs
    if net_records:
        for r in net_records:
            del r["_topic"]
        df_net = pl.DataFrame(net_records)
        df_net = df_net.with_columns(
            # FIX: Added time_zone and strict tracking to safely handle string parsing
            pl.col("timestamp").str.to_datetime(time_zone="UTC", strict=False).alias("timestamp"),
            pl.col("timestamp").str.slice(0, 10).alias("date")
        )
        # Write append mode partitioned by date
        df_net.write_delta(
            NETWORK_DELTA_PATH,
            mode="append",
            delta_write_options={"partition_by": ["date"]}
        )
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Wrote {len(df_net)} network records to Delta Lake.")

    # Process Endpoint Logs
    if sys_records:
        for r in sys_records:
            del r["_topic"]
        df_sys = pl.DataFrame(sys_records)
        df_sys = df_sys.with_columns(
            # FIX: Added time_zone and strict tracking to safely handle string parsing
            pl.col("timestamp").str.to_datetime(time_zone="UTC", strict=False).alias("timestamp"),
            pl.col("timestamp").str.slice(0, 10).alias("date")
        )
        df_sys.write_delta(
            ENDPOINT_DELTA_PATH,
            mode="append",
            delta_write_options={"partition_by": ["date"]}
        )
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Wrote {len(df_sys)} endpoint records to Delta Lake.")

def main():
    print("Starting Streaming Delta Lake Consumer...")
    records_buffer = []
    last_flush = time.time()

    try:
        while True:
            msg = consumer.poll(timeout=1.0)

            if msg is None:
                if records_buffer and (time.time() - last_flush >= BATCH_TIMEOUT):
                    write_batch_to_delta(records_buffer)
                    consumer.commit()
                    records_buffer.clear()
                    last_flush = time.time()
                continue

            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    print(f"Consumer error: {msg.error()}")
                continue

            # Parse message payload
            payload = json.loads(msg.value().decode('utf-8'))
            payload["_topic"] = msg.topic()
            records_buffer.append(payload)

            # Flush condition check
            if len(records_buffer) >= BATCH_SIZE or (time.time() - last_flush >= BATCH_TIMEOUT):
                write_batch_to_delta(records_buffer)
                consumer.commit()
                records_buffer.clear()
                last_flush = time.time()

    except KeyboardInterrupt:
        print("\nShutting down consumer...")
    finally:
        consumer.close()

if __name__ == "__main__":
    main()
