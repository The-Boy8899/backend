import sqlite3
from pathlib import Path

DB_PATH = Path("community_id.db")

conn = sqlite3.connect(str(DB_PATH))
c = conn.cursor()
c.execute("SELECT member_id, name, expiry FROM members WHERE member_id IN ('D6F46A03', 'TEST001', '696F6C03')")
rows = c.fetchall()
print("Members in DB:")
for row in rows:
    print(f"  {row[0]}: {row[1]} - {row[2]} (type: {type(row[2]).__name__})")
conn.close()
