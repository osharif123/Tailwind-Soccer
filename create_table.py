import MySQLdb

config = {
    'user': 'u390839445_Omar',
    'passwd': 'Bismillah123!',
    'host': 'srv959.hstgr.io',
    'db': 'u390839445_Sharif_users'
}

# Connect to the database
db = MySQLdb.connect(**config)
cursor = db.cursor()

# Create temporary table
create_query = """
CREATE TABLE events_temp (
    id TEXT,
    time TEXT,
    location TEXT,
    day TEXT
)
"""
try:
    cursor.execute(create_query)
    db.commit()
    print("Temporary table created successfully.")
except MySQLdb.Error as e:
    db.rollback()
    print("Error creating temporary table:", e)

# Copy data from original table to temporary table
copy_query = "INSERT INTO events_temp SELECT id, time, location, day FROM events"
try:
    cursor.execute(copy_query)
    db.commit()
    print("Data copied to temporary table successfully.")
except MySQLdb.Error as e:
    db.rollback()
    print("Error copying data to temporary table:", e)

# Drop the original table
drop_query = "DROP TABLE events"
try:
    cursor.execute(drop_query)
    db.commit()
    print("Original table dropped successfully.")
except MySQLdb.Error as e:
    db.rollback()
    print("Error dropping original table:", e)

# Rename temporary table to original table name
rename_query = "ALTER TABLE events_temp RENAME TO events"
try:
    cursor.execute(rename_query)
    db.commit()
    print("Temporary table renamed to 'events'.")
except MySQLdb.Error as e:
    db.rollback()
    print("Error renaming temporary table:", e)

# Close the database connection
db.close()
