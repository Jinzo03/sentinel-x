import duckdb
import lancedb
from langchain_core.tools import tool

DELTA_NET_PATH = "data/delta/network_logs"
DELTA_SYS_PATH = "data/delta/endpoint_logs"
LANCEDB_PATH = "data/lancedb"

@tool
def query_network_history(ip_address: str) -> str:
    """Queries historical network connections for a specific IP address from Delta Lake."""
    try:
        conn = duckdb.connect()
        conn.execute("INSTALL delta; LOAD delta;")
        
        query = f"""
            SELECT timestamp, src_ip, dst_ip, dst_port, orig_bytes, resp_bytes, proto
            FROM delta_scan('{DELTA_NET_PATH}')
            WHERE src_ip = '{ip_address}' OR dst_ip = '{ip_address}'
            ORDER BY timestamp DESC
            LIMIT 10
        """
        df = conn.execute(query).df()
        if df.empty:
            return f"No network records found for IP: {ip_address}"
        return df.to_json(orient="records")
    except Exception as e:
        return f"Error querying network logs: {str(e)}"

@tool
def query_endpoint_history(host_or_user: str) -> str:
    """Queries recent process execution logs for a specific host or user from Delta Lake."""
    try:
        conn = duckdb.connect()
        conn.execute("INSTALL delta; LOAD delta;")
        
        query = f"""
            SELECT timestamp, host, user, process_name, command_line
            FROM delta_scan('{DELTA_SYS_PATH}')
            WHERE host = '{host_or_user}' OR user LIKE '%{host_or_user}%'
            ORDER BY timestamp DESC
            LIMIT 10
        """
        df = conn.execute(query).df()
        if df.empty:
            return f"No endpoint records found for: {host_or_user}"
        return df.to_json(orient="records")
    except Exception as e:
        return f"Error querying endpoint logs: {str(e)}"

@tool
def search_threat_intelligence(query_text: str) -> str:
    """Performs vector search in LanceDB against MITRE ATT&CK and CISA KEV threat intel."""
    try:
        db = lancedb.connect(LANCEDB_PATH)
        table = db.open_table("threat_intel")
        results = table.search(query_text).limit(3).to_list()
        
        output = []
        for r in results:
            output.append({
                "id": r["id"],
                "source": r["source"],
                "title": r["title"],
                "description": r["description"]
            })
        return str(output)
    except Exception as e:
        return f"Error querying threat intelligence: {str(e)}"