import sys
import os
import subprocess
import time


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def run_script(path_parts):
    """Βοηθητική συνάρτηση για να τρέχει scripts σωστά σε Windows/Linux"""
    script_path = os.path.join(BASE_DIR, *path_parts)
    
    if not os.path.exists(script_path):
        print(f"Error: Το αρχείο {script_path} δεν βρέθηκε!")
        return

    print(f"Running: {path_parts[-1]}...")
    try:

        subprocess.run([sys.executable, script_path], check=True)
    except KeyboardInterrupt:
        print("\nStopped by user.")
    except subprocess.CalledProcessError as e:
        print(f"\nError occurred (Code {e.returncode}).")

def main():
    if len(sys.argv) < 2:
        print("Usage: python manage.py [init|run|sim|test]")
        print("   init  -> Initialize Database")
        print("   run   -> Run API Server")
        print("   sim   -> Run Vehicle Simulation")
        print("   test  -> Test Database Connection")
        return

    command = sys.argv[1]

    if command == "init":

        run_script(["api", "init_db.py"])
        
    elif command == "run":

        run_script(["api", "server.py"])
        
    elif command == "sim":


        if os.path.exists(os.path.join(BASE_DIR, "main.py")):
            run_script(["main.py"])
        else:
            run_script(["full_system.py"])

    elif command == "test":

        run_script(["test_db.py"])
        
    else:
        print(f"Unknown command: {command}")

if __name__ == "__main__":
    main()