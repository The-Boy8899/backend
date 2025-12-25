import sqlite3
conn = sqlite3.connect('community_id.db')
c = conn.cursor()
c.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = c.fetchall()
print('Tables in database:')
for t in tables:
    print(f'  {t[0]}')
conn.close()
