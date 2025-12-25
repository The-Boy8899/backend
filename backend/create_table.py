import sqlite3
conn = sqlite3.connect('community_id.db')
c = conn.cursor()

# Create card_reads table
c.execute('''CREATE TABLE IF NOT EXISTS card_reads
             (id INTEGER PRIMARY KEY AUTOINCREMENT,
              member_id TEXT NOT NULL,
              timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
              status TEXT,
              FOREIGN KEY(member_id) REFERENCES members(member_id))''')

conn.commit()
conn.close()

print('Created card_reads table')
