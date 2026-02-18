import sqlite3
import datetime
import os


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "hev_metrics.db")

def log_telemetry(speed: float, battery: float, temp: float, source: str = "API"):
    """
    Καταγράφει μια νέα εγγραφή τηλεμετρίας στη βάση δεδομένων.
    
    Args:
        speed (float): Ταχύτητα σε km/h
        battery (float): Μπαταρία % (SoC)
        temp (float): Θερμοκρασία κινητήρα
        source (str): Από πού ήρθε η εγγραφή (π.χ. 'API', 'Simulation')
    """
    try:

        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            

            timestamp = datetime.datetime.now().isoformat()
            
          
            cursor.execute('''
                INSERT INTO telemetry (timestamp, speed_kmh, battery_soc, motor_temp, log_source)
                VALUES (?, ?, ?, ?, ?)
            ''', (timestamp, speed, battery, temp, source))#Kanei insert mia nea grammi sto telemetry me timestamp, speed, battery, temperature kai source, xrisimopoiwntas asfali parametrized query.
            
           

    except sqlite3.OperationalError:
        print(f"Database Error: Ο πίνακας 'telemetry' δεν βρέθηκε στο {DB_PATH}.")
        print("Tip: Τρέξε 'python manage.py init' για να φτιάξεις τη βάση.")
    except Exception as e:
        print(f"Database Error: {e}")

def get_recent_logs(limit: int = 5):#To limit einai optional argument me default timi 5.
    """
    Επιστρέφει τις τελευταίες Ν εγγραφές (για έλεγχο/dashboard).
    """
    try:
        with sqlite3.connect(DB_PATH) as conn:#Anoigei sindesi me to SQLite database pou brisketai sto DB_PATH. To with einai context manager:Anoigei to connection.To kleinei automata molis teleiwsei to block.Den xreiazetai conn.close()
            conn.row_factory = sqlite3.Row 
            cursor = conn.cursor()
            
            cursor.execute(''' 
                SELECT * FROM telemetry 
                ORDER BY id DESC 
                LIMIT ?
            ''', (limit,))#SELECT \* → pare ola ta columns, ORDER BY id DESC → pare tis pio prosfates eggrafes, LIMIT ? → pare mono osa rows zitithikan, (limit,) → dinei tin timi sto placeholder me asfaleia
            
            rows = [dict(row) for row in cursor.fetchall()]#Pairnei ola ta apotelesmata tou SELECT kai ta epistrefei ws lista apo sqlite3.Row objects.Kanei loop se kathe row pou epestrepse to query.To dict(row) metatrepei to row se dictionary.

            return rows
    except Exception:
        return []