import sqlite3

print("🔄 Resetting Agent Warrant and Budget...")
cx = sqlite3.connect("nexus_secure.db")

# 1. Un-ban the agent
cx.execute("UPDATE warrants SET revoked = 0")

# 2. Clear old reservations so the $100 budget is fully restored
cx.execute("DELETE FROM reservations")

cx.commit()
cx.close()
print("✅ Agent Un-banned! 100$ budget restored.")