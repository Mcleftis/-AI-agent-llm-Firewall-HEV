import sys
import os
from dotenv import load_dotenv
load_dotenv()
import time
import random
import hashlib  # Security: Hashing
import logging  # IDS Logging
from flask import Flask, jsonify, request, abort
from flask_cors import CORS
from datetime import datetime

# --- AZURE CLOUD LIBRARY ---
from azure.storage.blob import BlobServiceClient

# --- LOCAL IMPORTS ---
# Προσθήκη του φακέλου thesis στο path για να βρει τα modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from db_logger import log_telemetry

# --- 🛡️ TPM SECURITY MODULE IMPORT (ΤΟ ΝΕΟ ΚΟΜΜΑΤΙ) ---
try:
    from api.tpm_module import TPMSecurityModule
    TPM_AVAILABLE = True
except ImportError:
    print("⚠️ Warning: tpm_module.py not found in 'api/' folder. Running without Hardware Signing.")
    TPM_AVAILABLE = False

# --- LOGGING SETUP (Local IDS) ---
logging.basicConfig(filename='intrusion_attempts.log', level=logging.WARNING, 
                    format='%(asctime)s - %(message)s')

# --- IMPORTS ΜΕ ΑΣΦΑΛΕΙΑ (Fallback αν λείπουν) ---
try:
    from full_system import get_driver_intent
    AI_AVAILABLE = True
except ImportError:
    print("⚠️ Warning: full_system.py not found. Using Mock AI.")
    AI_AVAILABLE = False

try:
    import rust_can_firewall 
    RUST_AVAILABLE = True
except ImportError:
    print("⚠️ Warning: Rust module not found. Running in Python Simulation Mode.")
    RUST_AVAILABLE = False

app = Flask(__name__)
CORS(app)

BASE_URL = '/api/v1'

# ==============================================================================
# 🔐 SECURITY CONFIGURATION
# ==============================================================================

# 1. TOKEN HASHING (SHA-256)
STORED_TOKEN_HASH = os.getenv("TOKEN_HASH")

# 2. AZURE CLOUD CONFIG
AZURE_CONN_STRING = os.getenv("AZURE_STORAGE_KEY")
CONTAINER_NAME = "thesis-logs"

# 3. TPM HARDWARE INITIALIZATION 🛡️
hsm = None
if TPM_AVAILABLE:
    print("\n[TPM] 🔌 Initializing Hardware Security Module (SoftHSM)...")
    hsm = TPMSecurityModule()
    print("[TPM] ✅ Secure Enclave Ready. Private Key is SEALED.")

# ==============================================================================
# ☁️ CLOUD UPLOAD FUNCTION
# ==============================================================================
def upload_to_cloud(file_name):
    """
    REAL MODE: Στέλνει το log file στο Azure Storage για Forensic ανάλυση.
    """
    print(f"\n[CLOUD] ☁️ Initiating Upload to Azure Blob Storage...")
    
    try:
        if not AZURE_CONN_STRING:
             print("[CLOUD] ⚠️ No Azure Key found. Skipping upload.")
             return

        blob_service_client = BlobServiceClient.from_connection_string(AZURE_CONN_STRING)
        container_client = blob_service_client.get_container_client(CONTAINER_NAME)
        
        with open(file_name, "rb") as data:
            container_client.upload_blob(name=file_name, data=data, overwrite=True)
            
        print(f"[CLOUD] ✅ SUCCESS: File '{file_name}' secure in Azure Cloud!")
        
    except Exception as e:
        print(f"[CLOUD] ❌ ERROR: Upload failed. Reason: {e}")


# ==============================================================================
# 🧠 MAIN CONTROL ENDPOINT (ΤΩΡΑ ΜΕ ΥΠΟΓΡΑΦΗ TPM)
# ==============================================================================
@app.route(f'{BASE_URL}/control/intent', methods=['POST'])
def analyze_intent():
    # --- A. SECURE TOKEN VERIFICATION ---
    user_token = request.headers.get("X-Auth-Token")
    if not user_token: abort(401)

    input_hash = hashlib.sha256(user_token.encode()).hexdigest()
    if input_hash != STORED_TOKEN_HASH:
        logging.warning(f"IDS ALERT: Invalid Token Attempt from {request.remote_addr}")
        abort(401)

    # --- B. PARSE DATA ---
    try:
        data = request.json
        if not data: return jsonify({"error": "No JSON data"}), 400
        command = data.get("command", "")
    except:
        return jsonify({"error": "Bad Request"}), 400

    # --- C. IDS/IPS (SQL INJECTION) ---
    BAD_KEYWORDS = ["DROP", "DELETE", "SELECT", "INSERT", "--", "SCRIPT", "UNION"]
    if any(bad_word in command.upper() for bad_word in BAD_KEYWORDS):
        alert_msg = f"🛑 CRITICAL IDS ALERT: SQL Injection Detected! Cmd: '{command}' IP: {request.remote_addr}"
        print(alert_msg)
        logging.critical(alert_msg)
        upload_to_cloud('intrusion_attempts.log')
        return jsonify({"status": "BLOCKED", "reason": "Malicious SQL Pattern Detected"}), 403

    # --- D. RUST FIREWALL CHECK ---
    if RUST_AVAILABLE:
        try:
            if not rust_can_firewall.validate_command(command):
                logging.warning(f"RUST FIREWALL ALERT: Blocked '{command}'")
                return jsonify({"status": "BLOCKED", "reason": "Rust Firewall Rejected"}), 403
        except: pass

    # --- E. AI LOGIC ---
    ai_mode = "NORMAL_MODE"
    if AI_AVAILABLE:
        try:
            ai_mode = get_driver_intent(command)
        except: pass
        
        # Override Logic
        if any(x in command.lower() for x in ["fast", "speed", "sport"]):
             if "SPORT" not in str(ai_mode).upper():
                 print("⚡ FORCE OVERRIDE: Keyword detected -> Switching to SPORT")
                 ai_mode = "SPORT_MODE"

    # --- F. FINAL RESPONSE & TPM SIGNING 🛡️ ---
    mode_result = "SPORT" if "SPORT" in str(ai_mode).upper() else "NORMAL"
    
    response_payload = {
        "status": "APPROVED",
        "selected_mode": mode_result,
        "reasoning": f"AI output: {ai_mode}",
        "execution_time": 0.5,
        "throttle_sensitivity": 0.9 if mode_result == "SPORT" else 0.5
    }

    # ΕΔΩ ΓΙΝΕΤΑΙ ΤΟ ΜΑΓΙΚΟ: ΥΠΟΓΡΑΦΗ ΜΕ ΤΟ "CHIP"
    if hsm:
        # Υπογράφουμε το αποτέλεσμα (mode_result) για να αποδείξουμε ότι βγήκε από εμάς
        signature = hsm.sign_data(mode_result.encode('utf-8'))
        response_payload["tpm_signature"] = signature.hex()
        response_payload["security_verification"] = "SIGNED_BY_TPM_2.0"

    return jsonify(response_payload)


# ==============================================================================
# 📡 TELEMETRY ENDPOINT
# ==============================================================================
@app.route(f'{BASE_URL}/vehicle/telemetry', methods=['GET'])
def get_telemetry():
    current_speed = round(random.uniform(50, 120), 1)
    current_battery = round(random.uniform(30, 90), 1)
    current_temp = round(random.uniform(70, 95), 1)
    
    try:
        log_telemetry(current_speed, current_battery, current_temp, source="API")
    except: pass

    return jsonify({
        "timestamp": datetime.now().isoformat(),
        "speed_kmh": current_speed,
        "battery_soc": current_battery,
        "motor_temp": current_temp,
        "ai_reasoning": "Vehicle operating within normal parameters." 
    })

# ==============================================================================
# 🛡️ SECURITY IDENTITY ENDPOINT (ΝΕΟ)
# ==============================================================================
@app.route(f'{BASE_URL}/security/verify-identity', methods=['GET'])
def verify_identity():
    """
    Endpoint για να δει ο Client (Streamlit) το Public Key μας
    και να επιβεβαιώσει την υπογραφή TPM.
    """
    if not hsm:
        return jsonify({"error": "TPM Module not loaded"}), 500
        
    public_key_pem = hsm.get_public_key()
    
    return jsonify({
        "server_name": "Thesis IoT Controller (Secure Boot)",
        "security_level": "TPM 2.0 Hardware Backed",
        "public_key": public_key_pem.decode('utf-8'),
        "status": "TRUSTED"
    })

@app.route(f'{BASE_URL}/security/status', methods=['GET'])
def get_security_status():
    firewall = "ACTIVE (Rust Engine v2.0)" if RUST_AVAILABLE else "SIMULATION"
    tpm_stat = "ACTIVE (Hardware Backed)" if hsm else "INACTIVE"
    
    return jsonify({
        "timestamp": datetime.now().isoformat(),
        "firewall_status": firewall,
        "tpm_module": tpm_stat,
        "ids_status": "LOGGING ENABLED",
        "cloud_sync": "AZURE BLOB STORAGE (GERMANY)"
    })

# ==============================================================================
# 🚀 SERVER START
# ==============================================================================
if __name__ == '__main__':
    # SSL Setup
    cert_file = os.path.join('certs', 'cert.pem')
    key_file = os.path.join('certs', 'key.pem')
    
    print("\n" + "="*50)
    print("🚦 HYBRID AI VEHICLE CONTROL SYSTEM v3.0 (FINAL)")
    print("🔒 SECURITY STACK:")
    print("   1. NETWORK: Cloudflare Tunnel & SSL/TLS")
    print("   2. AUTH: SHA-256 Token Hashing")
    print("   3. HARDWARE: TPM 2.0 Key Storage (Simulated)")
    print("   4. LOGGING: Azure Blob Storage (Germany)")
    print("="*50 + "\n")
    
    # Χρησιμοποιούμε τα "χειροποίητα" πιστοποιητικά για το HTTPS (Transport Layer)
    # Το TPM χρησιμοποιείται για το Data Signing (Application Layer)
    if os.path.exists(cert_file) and os.path.exists(key_file):
        ssl_context = (cert_file, key_file)
        app.run(host='0.0.0.0', port=5000, debug=False, ssl_context=ssl_context)
    else:
        print("⚠️ SSL Certs not found. Running in HTTP mode (Not secure).")
        app.run(host='0.0.0.0', port=5000, debug=False)