import sqlite3
conn = sqlite3.connect('community_id.db')
c = conn.cursor()
c.execute("SELECT member_id, name, expiry FROM members WHERE member_id = 'TEST001'")
result = c.fetchone()
print('TEST001 record:', result)
conn.close()
