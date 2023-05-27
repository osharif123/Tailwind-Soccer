import MySQLdb

config = {
    'user': 'u390839445_Omar',
    'passwd': 'Bismillah123!',
    'host': 'srv959.hstgr.io',
    'db': 'u390839445_Sharif_users'
}

def retrieve_table_columns(config):
    conn = None
    try:
        print('Connecting to MySQL database...')
        conn = MySQLdb.connect(**config)
        if conn:
            print('Connection to MySQL database successful')

            cursor = conn.cursor()

            # Retrieve table names
            cursor.execute("SHOW TABLES")
            tables = cursor.fetchall()

            # Iterate over tables
            for table in tables:
                table_name = table[0]
                print(f"Table: {table_name}")
                print("Columns:")

                # Retrieve column names for each table
                cursor.execute(f"SHOW COLUMNS FROM {table_name}")
                columns = cursor.fetchall()

                # Print column names
                for column in columns:
                    column_name = column[0]
                    print(column_name)

                print()  # Print a blank line between tables

            cursor.close()
        else:
            print('Connection to MySQL database failed')

    except MySQLdb.OperationalError as e:
        print('Error occurred:', e)
    finally:
        if conn:
            conn.close()
            print('MySQL connection closed')

retrieve_table_columns(config)
