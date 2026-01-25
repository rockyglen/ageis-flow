# mcp_server/database.py
import sqlite3
import os

# Store DB in the root directory so everyone can find it
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "aegis_state.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS compliance_checks (
            id TEXT PRIMARY KEY,
            name TEXT,
            description TEXT,
            status TEXT
        )
    ''')
    
    # Initialize with default SAFE state (or Unknown)
    initial_data = [
        ("check_iam", "IAM Privilege Escalation", "Ensures no unauthorized Admin users", "SAFE"),
        ("check_s3", "S3 Data Leakage", "Prevents Public Access to Buckets", "SAFE"),
        ("check_ssh", "Network Exposure", "Restricts Port 22 (SSH) Access", "SAFE"),
        ("check_ec2", "Compute Hardening", "Enforces IMDSv2 & Encryption", "SAFE"),
        ("check_vpc", "Network Logging", "Ensures VPC Flow Logs are Active", "SAFE"),
    ]
    
    for row in initial_data:
        c.execute("INSERT OR IGNORE INTO compliance_checks VALUES (?, ?, ?, ?)", row)
    
    conn.commit()
    conn.close()

def update_status(check_id: str, status: str):
    """Status options: SAFE, VULNERABLE"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE compliance_checks SET status = ? WHERE id = ?", (status, check_id))
    conn.commit()
    conn.close()

def get_all_status():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM compliance_checks")
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows

def reset_to_vulnerable():
    """Called by Server when Terraform runs"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Set all to VULNERABLE
    c.execute("UPDATE compliance_checks SET status = 'VULNERABLE'")
    conn.commit()
    conn.close()

# Initialize on import
init_db()