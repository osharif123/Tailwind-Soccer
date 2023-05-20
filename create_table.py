import MySQLdb

config = {
    'user': 'u390839445_Omar',
    'passwd': 'Bismillah123!',
    'host': 'srv959.hstgr.io',
    'db': 'u390839445_Sharif_users'
}

def test_mysqldb_connection(config):
    conn = None
    try:
        print('Connecting to MySQL database...')
        conn = MySQLdb.connect(**config)

        if conn:
            print('Connection to MySQL database successful')
        else:
            print('Connection to MySQL database failed')
    except MySQLdb.OperationalError as e:
        print('Error occurred:', e)
    finally:
        if conn:
            conn.close()
            print('MySQL connection closed')

test_mysqldb_connection(config)
