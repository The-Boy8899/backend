import sqlite3
conn = sqlite3.connect('community_id.db')
c = conn.cursor()
c.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = [row[0] for row in c.fetchall()]
print("Tables:", tables)
for table in tables:
    c.execute(f"PRAGMA table_info({table});")
    columns = c.fetchall()
    print(f"\n{table} columns:")
    for col in columns:
        print(f"  {col[1]} ({col[2]})")
    c.execute(f"SELECT COUNT(*) FROM {table};")
    count = c.fetchone()[0]
    print(f"  Rows: {count}")
conn.close()
