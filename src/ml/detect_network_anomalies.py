import duckdb
import joblib
import numpy as np
import polars as pl
from sklearn.ensemble import IsolationForest

DELTA_NET_PATH = "data/delta/network_logs"
MODEL_SAVE_PATH = "src/ml/isolation_forest_net.joblib"

def load_network_features():
    """Queries Delta Lake via DuckDB to pull feature vectors for ML training."""
    conn = duckdb.connect()
    conn.execute("INSTALL delta; LOAD delta;")
    
    query = f"""
        SELECT 
            uid,
            src_ip,
            dst_ip,
            dst_port,
            orig_bytes,
            resp_bytes,
            proto
        FROM delta_scan('{DELTA_NET_PATH}')
    """
    df = conn.execute(query).pl()
    return df

def train_and_predict():
    print("Loading network telemetry features from Delta Lake...")
    df = load_network_features()

    if df.is_empty():
        print("No network logs found. Run the producer and consumer first!")
        return

    print(f"Loaded {len(df)} connection records.")

    # Feature Engineering: One-hot encode protocol & scale numeric features
    # Numerical features: dst_port, orig_bytes, resp_bytes
    features_df = df.select([
        pl.col("dst_port").cast(pl.Float64),
        pl.col("orig_bytes").cast(pl.Float64),
        pl.col("resp_bytes").cast(pl.Float64),
        (pl.col("proto") == "tcp").cast(pl.Float64).alias("is_tcp"),
        (pl.col("proto") == "udp").cast(pl.Float64).alias("is_udp")
    ])

    X = features_df.to_numpy()

    # Train Isolation Forest (Contamination set to ~5% based on our synthetic anomaly generator)
    print("Training Isolation Forest model...")
    model = IsolationForest(
        n_estimators=100, 
        contamination=0.05, 
        random_state=42
    )
    
    # Fit model and predict (-1 = anomaly, 1 = normal)
    predictions = model.fit_predict(X)
    scores = model.decision_function(X)  # Lower/negative score = more anomalous

    # Attach predictions back to the original DataFrame
    df_results = df.with_columns([
        pl.Series("is_anomaly", predictions == -1),
        pl.Series("anomaly_score", scores)
    ])

    # Save model artifact
    joblib.dump(model, MODEL_SAVE_PATH)
    print(f"Model saved to {MODEL_SAVE_PATH}")

    # Inspect Top Flagged Anomalies
    anomalies = df_results.filter(pl.col("is_anomaly")).sort("anomaly_score")
    
    print("\n=== Top Flagged Network Anomalies (Isolation Forest) ===")
    print(
        anomalies.select(["src_ip", "dst_ip", "dst_port", "orig_bytes", "resp_bytes", "anomaly_score"])
        .head(10)
    )

if __name__ == "__main__":
    train_and_predict()