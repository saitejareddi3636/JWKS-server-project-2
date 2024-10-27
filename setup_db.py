import sqlite3

# Create/open a SQLite database file
conn = sqlite3.connect('totally_not_my_privateKeys.db')
cursor = conn.cursor()

# Create table if it doesn't exist, with kid as INTEGER
cursor.execute('''
    CREATE TABLE IF NOT EXISTS keys (
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
''')
conn.commit()
conn.close()
