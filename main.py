import argparse
import logging
import sys
import os
import hashlib  # <--- ΤΟ ΠΡΟΣΘΕΣΑΜΕ ΓΙΑ ΤΗΝ ΑΣΦΑΛΕΙΑ

try:
    from profiling import measure_performance
except ImportError:
    def measure_performance(func): return func

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

# --- SECURITY FUNCTION ---
def verify_model_integrity(model_path_prefix: str) -> bool:
    """
    Ελέγχει αν το αρχείο του μοντέλου (.zip) ταιριάζει με την υπογραφή (.sha256).
    Λειτουργεί ως Firewall πριν φορτώσουμε το AI.
    """
    # Αν ο χρήστης δεν έδωσε path, ή το path είναι 'models/ppo_hev', προσθέτουμε την κατάληξη αν λείπει
    # Αλλά συνήθως η save_path στο AI_agent είναι χωρίς κατάληξη.
    
    model_file = f"{model_path_prefix}.zip"
    hash_file = f"{model_path_prefix}.sha256"

    # 1. Έλεγχος Υπαρξης Αρχείων
    if not os.path.exists(model_file):
        logging.error(f"[SECURITY] Model file missing: {model_file}")
        return False
    if not os.path.exists(hash_file):
        logging.warning(f"[SECURITY] Unsigned model detected (No .sha256 file). Risks exist.")
        # Εδώ αποφασίζεις: Το αφήνεις ή το κόβεις; 
        # Για Senior Security, κανονικά το κόβεις. Για demo, ίσως warning.
        # Ας είμαστε αυστηροί:
        logging.critical("[SECURITY BLOCK] Cannot verify integrity. System Halted.")
        return False

    # 2. Υπολογισμός Hash του αρχείου .zip
    sha256_hash = hashlib.sha256()
    with open(model_file, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    calculated_hash = sha256_hash.hexdigest()

    # 3. Ανάγνωση του Hash υπογραφής
    with open(hash_file, "r") as f:
        expected_hash = f.read().strip()

    # 4. Σύγκριση
    if calculated_hash == expected_hash:
        logging.info("[SECURITY] Integrity Verified. Model is authentic.")
        return True
    else:
        logging.critical("[SECURITY ALERT] HASH MISMATCH! The model file has been altered/hacked.")
        logging.critical(f"Expected: {expected_hash}")
        logging.critical(f"Actual:   {calculated_hash}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Neuro-Symbolic HEV Control System CLI")
    
    parser.add_argument(
        '--mode',
        type=str, 
        choices=['train', 'evaluate', 'demo', 'ablation', 'optimize'],
        required=True,
        help='Select operation mode'
    )

    parser.add_argument('--steps', type=int, default=100000, help='Training steps')
    parser.add_argument('--lr', type=float, default=0.0003, help='Learning rate')
    parser.add_argument('--traffic', type=str, default='normal', choices=['low', 'normal', 'heavy'])
    parser.add_argument('--driver_mood', type=str, default='neutral', help='Prompt for Demo')
    
    # Προσοχή: Το default path πρέπει να ταιριάζει με αυτό που σώζει το AI_agent.py
    # Στο AI_agent βάλαμε: os.path.join(SCRIPT_DIR, "models", "ppo_hev")
    # Εδώ δίνουμε ένα σχετικό path, αρκεί να τρέχεις το main.py από τον σωστό φάκελο.
    parser.add_argument('--model_path', type=str, default='models/ppo_hev', help='Model file path (without .zip)')

    args = parser.parse_args()

    logging.info(f"Starting System in [{args.mode.upper()}] mode")
    
    try:
        # Lazy imports (για να μην φορτώνουμε τα πάντα αν δεν χρειάζεται)
        if args.mode == 'train':
            from AI_agent import train_ppo
            logging.info("Starting PPO Training...")
            measured_train = measure_performance(train_ppo)
            # Προσοχή: Το train_ppo πλέον σώζει το hash μόνο του.
            measured_train(steps=args.steps, lr=args.lr, traffic=args.traffic)
            logging.info("Training Done.")

        elif args.mode == 'demo':
            # --- SECURITY CHECK POINT ---
            # Πριν φορτώσουμε το demo, ελέγχουμε το μοντέλο!
            logging.info("Performing Security Scan on Model...")
            if not verify_model_integrity(args.model_path):
                sys.exit(1) # Κόβουμε την εκτέλεση αν αποτύχει ο έλεγχος

            from full_system import run_live_system
            logging.info("Initializing Live Demo...")
            measured_demo = measure_performance(run_live_system)
            measured_demo(prompt=args.driver_mood, model_path=args.model_path)
            
        elif args.mode == 'evaluate':
            # Και εδώ χρειάζεται έλεγχος, γιατί φορτώνουμε μοντέλο
            logging.info("Performing Security Scan on Model...")
            if not verify_model_integrity(args.model_path):
                sys.exit(1)

            from evaluate_agent import run_evaluation
            run_evaluation(model_path=args.model_path)

        elif args.mode == 'optimize':
            from optimize import run_grid_search
            logging.info("Starting Grid Search...")
            measured_opt = measure_performance(run_grid_search)
            measured_opt()

        elif args.mode == 'ablation':
            from run_ablation import run_study
            logging.info("Running Ablation Study...")
            measured_ablation = measure_performance(run_study)
            measured_ablation()
    
    except ImportError as e:
        logging.error(f"Could not import module: {e}")
        logging.error("Tip: Ensure all files (AI_agent.py, full_system.py, etc.) are in the same folder.")  

    except Exception as e:
        logging.error(f"Critical Error during execution: {e}", exc_info=True)

if __name__ == "__main__":
    main()