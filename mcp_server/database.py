import sqlite3
import os

# Try importing psycopg2 for Cloud SQL (PostgreSQL) support
try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    psycopg2 = None

# Store DB in the root directory so everyone can find it
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "aegis_state.db")

def get_db_type():
    """Returns 'postgres' if Cloud SQL env vars are detected, else 'sqlite'."""
    if os.environ.get("CLOUD_SQL_CONNECTION_NAME") or os.environ.get("DB_HOST"):
        return "postgres"
    return "sqlite"

def get_connection():
    """Establishes a connection to either SQLite or PostgreSQL."""
    if get_db_type() == "postgres":
        if not psycopg2:
            raise ImportError("psycopg2 module not found. Please install it to use PostgreSQL.")
        
        db_user = os.environ.get("DB_USER", "postgres")
        db_pass = os.environ.get("DB_PASS", "password")
        db_name = os.environ.get("DB_NAME", "aegis_db")
        
        # Option A: Cloud Run via Unix Socket (Recommended for Cloud Run)
        if os.environ.get("CLOUD_SQL_CONNECTION_NAME"):
            unix_socket = f"/cloudsql/{os.environ.get('CLOUD_SQL_CONNECTION_NAME')}"
            return psycopg2.connect(user=db_user, password=db_pass, dbname=db_name, host=unix_socket)
        
        # Option B: TCP Connection (Local dev or specific host)
        return psycopg2.connect(
            user=db_user, 
            password=db_pass, 
            dbname=db_name, 
            host=os.environ.get("DB_HOST", "localhost"),
            port=os.environ.get("DB_PORT", "5432")
        )
    else:
        # Fallback to SQLite
        return sqlite3.connect(DB_PATH)

def init_db():
    db_type = get_db_type()
    print(f"[DB] Initializing database mode: {db_type.upper()}")
    conn = get_connection()
    c = conn.cursor()
    
    # Create table (Syntax is compatible with both for this simple schema)
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
        if db_type == "postgres":
            # Postgres syntax: ON CONFLICT DO NOTHING
            c.execute("INSERT INTO compliance_checks VALUES (%s, %s, %s, %s) ON CONFLICT (id) DO NOTHING", row)
        else:
            # SQLite syntax: INSERT OR IGNORE
            c.execute("INSERT OR IGNORE INTO compliance_checks VALUES (?, ?, ?, ?)", row)
    
    conn.commit()
    conn.close()

def update_status(check_id: str, status: str):
    """Status options: SAFE, VULNERABLE"""
    conn = get_connection()
    c = conn.cursor()
    
    if get_db_type() == "postgres":
        c.execute("UPDATE compliance_checks SET status = %s WHERE id = %s", (status, check_id))
    else:
        c.execute("UPDATE compliance_checks SET status = ? WHERE id = ?", (status, check_id))
        
    conn.commit()
    conn.close()

def get_all_status():
    conn = get_connection()
    
    if get_db_type() == "postgres":
        # Use RealDictCursor to get dictionary-like results
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM compliance_checks")
        rows = [dict(row) for row in cur.fetchall()]
    else:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM compliance_checks")
        rows = [dict(row) for row in c.fetchall()]
        
    conn.close()
    return rows

def reset_to_vulnerable():
    """Called by Server when Terraform runs"""
    conn = get_connection()
    c = conn.cursor()
    # Set all to VULNERABLE
    c.execute("UPDATE compliance_checks SET status = 'VULNERABLE'")
    conn.commit()
    conn.close()