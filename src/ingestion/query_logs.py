import duckdb

def analyze_logs():
    conn = duckdb.connect()

    # Enable Delta Lake extension in DuckDB
    conn.execute("INSTALL delta; LOAD delta;")

    print("=== Network Log Egress Summary (Top Source IPs) ===")
    net_query = """
        SELECT 
            src_ip, 
            COUNT(*) as total_connections,
            SUM(orig_bytes) as total_sent_bytes,
            AVG(orig_bytes) as avg_bytes_per_conn
        FROM delta_scan('data/delta/network_logs')
        GROUP BY src_ip
        ORDER BY total_sent_bytes DESC
        LIMIT 5;
    """
    df_net = conn.execute(net_query).df()
    print(df_net.to_string(index=False))

    print("\n=== Suspicious Process Execution Summary ===")
    sys_query = """
        SELECT 
            host, 
            user, 
            process_name, 
            command_line, 
            COUNT(*) as exec_count
        FROM delta_scan('data/delta/endpoint_logs')
        WHERE command_line LIKE '%-enc%' OR process_name = 'powershell.exe'
        GROUP BY host, user, process_name, command_line
        ORDER BY exec_count DESC;
    """
    df_sys = conn.execute(sys_query).df()
    print(df_sys.to_string(index=False))

if __name__ == "__main__":
    analyze_logs()