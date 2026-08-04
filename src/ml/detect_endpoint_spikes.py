import duckdb
import polars as pl

DELTA_SYS_PATH = "data/delta/endpoint_logs"

def detect_volumetric_spikes():
    conn = duckdb.connect()
    conn.execute("INSTALL delta; LOAD delta;")

    print("Querying endpoint logs for volumetric process analysis...")
    
    # 1. Aggregate process count by 1-minute windows per host and process_name
    query = f"""
        SELECT 
            time_bucket(INTERVAL '1 minute', timestamp) AS window_time,
            host,
            process_name,
            COUNT(*) AS exec_count
        FROM delta_scan('{DELTA_SYS_PATH}')
        GROUP BY window_time, host, process_name
        ORDER BY window_time ASC
    """
    
    df = conn.execute(query).pl()

    if df.is_empty():
        print("No endpoint logs found in Delta Lake. Make sure consumer is running!")
        return

    print(f"Aggregated into {len(df)} 1-minute window metrics.")

    # 2. Compute dynamic mean and standard deviation per host/process
    # We use a window function in Polars to calculate Z-Score
    df_analyzed = df.with_columns([
        pl.col("exec_count").mean().over(["host", "process_name"]).alias("avg_exec_count"),
        pl.col("exec_count").std().over(["host", "process_name"]).alias("std_exec_count")
    ])

    # 3. Calculate Z-score (handle division by zero if std is 0)
    df_analyzed = df_analyzed.with_columns(
        pl.when(pl.col("std_exec_count") > 0)
        .then((pl.col("exec_count") - pl.col("avg_exec_count")) / pl.col("std_exec_count"))
        .otherwise(0.0)
        .alias("z_score")
    )

    # 4. Flag process windows where Z-Score breaches threshold (> 2.5) or process is powershell.exe
    spikes = df_analyzed.filter(
        (pl.col("z_score") > 2.5) | (pl.col("process_name") == "powershell.exe")
    ).sort("z_score", descending=True)

    print("\n=== Top Endpoint Volumetric Spikes & Suspicious Processes ===")
    print(
        spikes.select(["window_time", "host", "process_name", "exec_count", "avg_exec_count", "z_score"])
        .head(15)
    )

if __name__ == "__main__":
    detect_volumetric_spikes()