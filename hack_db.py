import sqlite3
conn = sqlite3.connect('nexus_secure.db')
# Hacker ne chupke se database mein $40 ko $1 bana diya
conn.execute("UPDATE trace_log SET body = replace(body, '40.00', '1.00')")
conn.commit()
print("Database Tampered Successfully!")