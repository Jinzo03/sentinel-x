import requests
import lancedb
from lancedb.pydantic import LanceModel, Vector
from lancedb.embeddings import get_registry

# Set up LanceDB embedding function
db = lancedb.connect("data/lancedb")
func = get_registry().get("sentence-transformers").create(name="all-MiniLM-L6-v2")

class ThreatIntelRecord(LanceModel):
    id: str
    source: str           # "MITRE_ATTACK" or "CISA_KEV"
    title: str
    description: str
    vector: Vector(func.ndims()) = func.VectorField()

# 1. Curated MITRE ATT&CK Core Techniques
MITRE_TECHNIQUES = [
    {
        "id": "T1071.004",
        "source": "MITRE_ATTACK",
        "title": "Application Layer Protocol: DNS Tunneling",
        "description": "Adversaries may communicate using DNS requests to covertly exfiltrate data or command and control host systems. Look for unusually large byte size in DNS queries or frequent high-frequency request rates."
    },
    {
        "id": "T1059.001",
        "source": "MITRE_ATTACK",
        "title": "Command and Scripting Interpreter: PowerShell",
        "description": "Adversaries may use PowerShell to execute commands, scripts, and malicious binaries. Encoded command flags (-enc, -encodedcommand) are frequently used to evade command-line inspection."
    },
    {
        "id": "T1110.001",
        "source": "MITRE_ATTACK",
        "title": "Brute Force: Password Guessing",
        "description": "Adversaries may attempt to gain access by systematically guessing passwords for existing system or domain accounts. Look for abnormal high volume failed authentication events over short time windows."
    },
    {
        "id": "T1021.002",
        "source": "MITRE_ATTACK",
        "title": "Remote Services: SMB/Windows Admin Shares",
        "description": "Adversaries may use SMB to laterally move through a network by accessing administrative shares (C$, ADMIN$) with privileged domain user credentials."
    }
]

def fetch_cisa_kev_sample():
    """Fetches real sample entries from the live CISA Known Exploited Vulnerabilities catalog."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        vulns = data.get("vulnerabilities", [])[:50]  # Take top 50 active vulnerabilities
        
        records = []
        for v in vulns:
            records.append({
                "id": v.get("cveID", "UNKNOWN"),
                "source": "CISA_KEV",
                "title": f"{v.get('vendorProject')} {v.get('product')} - {v.get('vulnerabilityName')}",
                "description": f"{v.get('shortDescription')} Required Action: {v.get('requiredAction')}"
            })
        print(f"Successfully fetched {len(records)} active CVEs from CISA KEV.")
        return records
    except Exception as e:
        print(f"Warning: Could not fetch CISA KEV dynamically ({e}). Using baseline MITRE set only.")
        return []

def main():
    print("Seeding Threat Intelligence Vector Store in LanceDB...")
    
    cisa_records = fetch_cisa_kev_sample()
    all_intel = MITRE_TECHNIQUES + cisa_records

    # Re-create table
    table_name = "threat_intel"
    table = db.create_table(table_name, schema=ThreatIntelRecord, mode="overwrite")
    
    # Add records (LanceDB automatically embeds 'description' using the sentence-transformer)
    table.add(all_intel)
    
    print(f"Successfully indexed {len(all_intel)} threat intelligence entries into LanceDB.")

    # Test Vector Query
    test_query = "encoded powershell execution hidden window"
    print(f"\nTesting Vector Search for query: '{test_query}'")
    results = table.search(test_query).limit(2).to_list()
    
    for r in results:
        print(f" -> [{r['source']}] {r['id']} - {r['title']} (Distance: {round(r['_distance'], 4)})")

if __name__ == "__main__":
    main()