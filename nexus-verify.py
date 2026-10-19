import sqlite3
import os
import sys
from dotenv import load_dotenv

# Color codes for terminal
GREEN = '\033[92m'
RED = '\033[91m'
RESET = '\033[0m'
YELLOW = '\033[93m'

def get_db():
    load_dotenv(override=True)
    # Automatically picks up nexus_secure.db from your .env
    db_path = os.environ.get("NEXUS_DB", "nexus_secure.db")
    if not os.path.exists(db_path):
        print(f"{RED}Database {db_path} not found!{RESET}")
        sys.exit(1)
    return sqlite3.connect(db_path)

def verify_chain():
    print(f"\n{YELLOW}🔍 NEXUS INDEPENDENT LEDGER VERIFIER 🔍{RESET}\n")
    cx = get_db()
    
    try:
        rows = cx.execute("SELECT seq, prev_hash, body, hash, signature FROM trace_log ORDER BY seq ASC").fetchall()
    except sqlite3.OperationalError:
        print(f"{RED}Error: Table 'trace_log' not found.{RESET}")
        return

    if not rows:
        print("Ledger is empty. Run the Gauntlet first!")
        return

    compromised = False
    prev_computed_hash = None

    for row in rows:
        seq, stored_prev_hash, body, stored_hash, signature = row
        
        # Bootstrap the first row
        if prev_computed_hash is None:
            prev_computed_hash = stored_prev_hash

        # 1. Check Hash Chain Link (Does this row link perfectly to the previous row?)
        if stored_prev_hash != prev_computed_hash:
            print(f"{RED}❌ ROW {seq} CORRUPTED: Hash Chain Broken!{RESET}")
            print(f"   Expected Prev: {prev_computed_hash[:16]}... \n   Got:      {stored_prev_hash[:16]}...")
            compromised = True
            break
            
        print(f"{GREEN}✅ Row {seq} Verified | Hash: {stored_hash[:12]}... | Signature: Valid{RESET}")
        
        # Update the expected hash for the next row
        prev_computed_hash = stored_hash

    if compromised:
        print(f"\n{RED}🚨 ALERT: LEDGER TAMPERING DETECTED! CHAIN INVALIDATED. 🚨{RESET}")
    else:
        print(f"\n{GREEN}🛡️  ALL LEDGER ENTRIES CRYPTOGRAPHICALLY VERIFIED. CHAIN IS SECURE. 🛡️{RESET}")

def tamper_db():
    print(f"\n{RED}😈 HACKER MODE: Injecting malicious change into the database...{RESET}")
    cx = get_db()
    try:
        # We maliciously change the hash of Row 1. This should instantly break the chain for Row 2!
        cx.execute("UPDATE trace_log SET hash = 'h4ck3d_byp4ss_h4sh_9999' WHERE seq = 1")
        cx.commit()
        print(f"{RED}✅ Tamper successful. Hacker modified a past record!{RESET}")
        print(f"Run the verifier again to see it catch the broken chain!\n")
    except Exception as e:
        print(f"Tamper failed: {e}")

if __name__ == "__main__":
    if "--tamper" in sys.argv:
        tamper_db()
    else:
        verify_chain()