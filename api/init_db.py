import sqlite3
import os


DB_NAME = "hev_metrics.db"
SCHEMA_FILE = "schema.sql"


base_path = os.path.dirname(__file__)
db_path = os.path.join(base_path, DB_NAME)
schema_path = os.path.join(base_path, SCHEMA_FILE)

print(f"Initializing Database from {SCHEMA_FILE}...")

try:

    conn = sqlite3.connect(db_path)#Anoigei sindesi me ena SQLite database file.To db_path einai to monopati tou arxeiou (px. "telemetry.db").An to arxeio den yparxei, to SQLite to ftiaxnei automata.
    cursor = conn.cursor()#Ftiaxnei ena cursor object, to opoio einai to “ergaleio” pou steilei entoles sto database.


    with open(schema_path, 'r', encoding='utf-8') as f:#Anoigeis ena arxeio gia diavasma, to onomazeis f, kai to Python to kleinei mono tou molis teleioseis.
        sql_script = f.read()


    cursor.executescript(sql_script)
    
    conn.commit()#Kane save o,ti ekana sto database
    conn.close()#Kleinei to database connection swsta kai kathara
    print("Success! Database schema applied.")
    print(f"Database file location: {db_path}")

except Exception as e:
    print(f"Error executing SQL: {e}")