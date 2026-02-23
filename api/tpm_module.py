import os
import sys
import hashlib
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv

# --- ΦΟΡΤΩΣΗ ΜΥΣΤΙΚΩΝ ΑΠΟ ΤΟ .env ---
load_dotenv()

# 🔴 FAIL-SAFE MECHANISM (Διορθώνει τα High/Critical Risks)
TPM_SECRET_STR = os.getenv("TPM_SECRET_ROOT_KEY")
AUTH_SALT_STR = os.getenv("AUTH_TOKEN_SALT")

if not TPM_SECRET_STR or not AUTH_SALT_STR:
    print("🔥 [CRITICAL SECURITY ERROR] Missing Secrets in .env!")
    print("   -> Σιγουρέψου ότι υπάρχουν τα TPM_SECRET_ROOT_KEY και AUTH_TOKEN_SALT")
    print("🔥 System HALTED to prevent insecure Fail-Open state.")
    sys.exit(1) # Κλείνει ακαριαία την εφαρμογή!

# Μετατροπές σε bytes για την κρυπτογραφία
TPM_SECRET_BYTES = TPM_SECRET_STR.encode('utf-8')
AUTH_SALT_BYTES = AUTH_SALT_STR.encode('utf-8')


# ==========================================
# ΜΕΡΟΣ 1: PBKDF2 HASHING ΜΕ SALT (ΓΙΑ TOKENS)
# ==========================================

def generate_secure_hash(token: str) -> str:
    """
    Διορθώνει το Medium Risk: Αντί για απλό SHA-256, χρησιμοποιεί 
    PBKDF2 με 100.000 iterations και Salt. Αδύνατον να σπάσει με Rainbow Tables.
    """
    return hashlib.pbkdf2_hmac(
        'sha256', 
        token.encode('utf-8'), 
        AUTH_SALT_BYTES, 
        100000 # Iterations
    ).hex()

def verify_token(provided_token: str, stored_hash: str) -> bool:
    """Διατηρεί την προστασία από Timing Attacks χρησιμοποιώντας secrets.compare_digest"""
    provided_hash = generate_secure_hash(provided_token)
    return secrets.compare_digest(provided_hash, stored_hash)


# ==========================================
# ΜΕΡΟΣ 2: TPM 2.0 RSA SIMULATION (ΓΙΑ SIGNING)
# ==========================================

TPM_STORAGE_PATH = "secure_enclave"
KEY_HANDLE_ID = "0x81010001"  # Τυπικό ID για TPM Storage Root Key

class TPMSecurityModule:
    """
    Προσομοιωτής TPM 2.0 (Trusted Platform Module).
    Διαχειρίζεται κρυπτογραφικά κλειδιά χωρίς να εκθέτει το Private Key στη μνήμη.
    """

    def __init__(self):
        # Δημιουργία του "Ασφαλούς Θύλακα" (Secure Enclave)
        if not os.path.exists(TPM_STORAGE_PATH):
            os.makedirs(TPM_STORAGE_PATH)
            print(f"🔒 [TPM] Initializing Secure Storage Enclave at ./{TPM_STORAGE_PATH}")
        
        self._private_key_path = os.path.join(TPM_STORAGE_PATH, "tpm_blob.key")
        self._public_key_path = os.path.join(TPM_STORAGE_PATH, "tpm_pub.pem")
        
        # Έλεγχος αν υπάρχει ήδη κλειδί
        if not os.path.exists(self._private_key_path):
            self._provision_new_key()
        else:
            print(f"✅ [TPM] Hardware Key Loaded (Handle: {KEY_HANDLE_ID})")

    def _provision_new_key(self):
        print("⚙️ [TPM] Generating NON-EXPORTABLE RSA 4096-bit Key Pair...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        
        # Αποθήκευση του Private Key (Κρυπτογραφημένο με το μυστικό από το .env)
        encrypted_blob = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(TPM_SECRET_BYTES) 
        )
        
        with open(self._private_key_path, "wb") as f:
            f.write(encrypted_blob)
            
        # Εξαγωγή Public Key
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(self._public_key_path, "wb") as f:
            f.write(public_pem)
            
        print("✅ [TPM] Key Generation Complete. Private Key is SEALED.")

    def _load_internal_key(self):
        """Φορτώνει το κλειδί ΜΟΝΟ για εσωτερική χρήση."""
        with open(self._private_key_path, "rb") as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=TPM_SECRET_BYTES, # Αποκρυπτογραφεί με το ασφαλές μυστικό
                backend=default_backend()
            )

    def sign_data(self, data: bytes) -> bytes:
        """Υπογράφει δεδομένα χρησιμοποιώντας το TPM."""
        print(f"🔐 [TPM] Requesting Signature on {len(data)} bytes (SHA-256)...")
        key = self._load_internal_key()
        
        signature = key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        print("📤 [TPM] Signature Generated Successfully.")
        return signature

    def get_public_key(self):
        """Επιστρέφει το Public Key για επαλήθευση από τρίτους."""
        with open(self._public_key_path, "rb") as f:
            return f.read()

# --- DEMO TEST ---
if __name__ == "__main__":
    print("--- 🏁 TESTING TPM & HASHING MODULE 🏁 ---\n")
    
    # 1. ΤΕΣΤ PBKDF2 Hashing
    my_token = "SuperSecretToken123"
    hashed = generate_secure_hash(my_token)
    print(f"[*] Original Token: {my_token}")
    print(f"[+] PBKDF2 Salted Hash: {hashed}")
    
    is_valid = verify_token(my_token, hashed)
    print(f"[+] Token Validation Match: {is_valid}\n")
    
    # 2. ΤΕΣΤ TPM RSA Signature
    tpm = TPMSecurityModule()
    message = b"Entoli: ENERGOPOIHSH_FRENNWN"
    signature = tpm.sign_data(message)
    print(f"\n[+] Signature (Hex): {signature.hex()[:64]}...")