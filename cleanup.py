import os

db_path = "nexus_secure.db"
if os.path.exists(db_path):
    os.remove(db_path)
    print("🗑️ Old secure database deleted successfully!")
else:
    print("⚠️ Database file not found, creating a fresh one.")