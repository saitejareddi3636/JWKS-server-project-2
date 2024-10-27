import sqlite3

# Connect to the SQLite database
conn = sqlite3.connect("totally_not_my_privateKeys.db")
cursor = conn.cursor()

# Check the table names in the database
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()

# Print the list of tables
print("Tables in the database:", tables)

# Close the connection
conn.close()
