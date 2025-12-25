import sqlite3
from pathlib import Path

db_path = Path("community_id.db")
conn = sqlite3.connect(db_path)
c = conn.cursor()

# Create members table
c.execute('''CREATE TABLE IF NOT EXISTS members
             (id INTEGER PRIMARY KEY AUTOINCREMENT,
              member_id TEXT UNIQUE NOT NULL,
              name TEXT NOT NULL,
              expiry TEXT NOT NULL,
              issued_at INTEGER NOT NULL,
              member_type TEXT DEFAULT 'member',
              status TEXT DEFAULT 'active',
              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
              updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

# Insert test member data from payload.json
test_members = [
    ("20092", "adeoye jospeh", "2024-08-02", 1609459200, "member", "active"),
    ("2EA66A03", "Test Member", "2025-12-31", 1609459200, "member", "active"),  # Test with card UID
]

for member_id, name, expiry, issued_at, member_type, status in test_members:
    try:
        c.execute('''INSERT INTO members (member_id, name, expiry, issued_at, member_type, status)
                    VALUES (?, ?, ?, ?, ?, ?)''',
                 (member_id, name, expiry, issued_at, member_type, status))
    except sqlite3.IntegrityError:
        print(f"Member {member_id} already exists")

conn.commit()

# Verify
c.execute("SELECT member_id, name, expiry, status FROM members;")
rows = c.fetchall()
print("Database initialized. Members:")
for row in rows:
    print(f"  {row[0]}: {row[1]} - {row[2]} ({row[3]})")

conn.close()
