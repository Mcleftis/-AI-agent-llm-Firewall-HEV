import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# --- ΡΥΘΜΙΣΕΙΣ TPM (ΠΡΟΣΟΜΟΙΩΣΗ) ---
TPM_STORAGE_PATH = "secure_enclave"
KEY_HANDLE_ID = "0x81010001"  # Τυπικό ID για TPM Storage Root Key

class TPMSecurityModule:
    """
    Προσομοιωτής TPM 2.0 (Trusted Platform Module).
    Διαχειρίζεται κρυπτογραφικά κλειδιά χωρίς να εκθέτει το Private Key στη μνήμη της εφαρμογής.
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
        """
        Εσωτερική διαδικασία (Provisioning). 
        Σε πραγματικό TPM, αυτό γίνεται μέσα στο Hardware (On-Chip Generation).
        """
        print("⚙️ [TPM] Generating NON-EXPORTABLE RSA 4096-bit Key Pair...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        
        # Αποθήκευση του Private Key (Σε πραγματικό σενάριο, αυτό μένει ΜΟΝΟ στο chip)
        # Εδώ το κρυπτογραφούμε για να προσομοιώσουμε την ασφάλεια
        encrypted_blob = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b"THESIS_SECRET_ROOT_KEY") 
        )
        
        with open(self._private_key_path, "wb") as f:
            f.write(encrypted_blob)
            
        # Εξαγωγή Public Key (Αυτό επιτρέπεται)
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(self._public_key_path, "wb") as f:
            f.write(public_pem)
            
        print("✅ [TPM] Key Generation Complete. Private Key is SEALED.")

    def _load_internal_key(self):
        """
        Φορτώνει το κλειδί ΜΟΝΟ για εσωτερική χρήση.
        Δεν επιστρέφεται ποτέ στον χρήστη.
        """
        with open(self._private_key_path, "rb") as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=b"THESIS_SECRET_ROOT_KEY",
                backend=default_backend()
            )

    def sign_data(self, data: bytes) -> bytes:
        """
        Υπογράφει δεδομένα χρησιμοποιώντας το TPM.
        Ο εξωτερικός χρήστης ΔΕΝ βλέπει ποτέ το κλειδί, παίρνει μόνο την υπογραφή.
        """
        print(f"🔐 [TPM] Requesting Signature on {len(data)} bytes (SHA-256)...")
        
        # Φόρτωση στο "Hardware"
        key = self._load_internal_key()
        
        # Υπογραφή
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
        """
        Επιστρέφει το Public Key για επαλήθευση από τρίτους.
        """
        with open(self._public_key_path, "rb") as f:
            return f.read()

# --- DEMO TEST (Αν το τρέξεις μόνο του) ---
if __name__ == "__main__":
    tpm = TPMSecurityModule()
    
    # Δεδομένα προς υπογραφή
    message = b"Entoli: ENERGOPOIHSH_FRENNWN"
    
    # 1. Υπογραφή (Χωρίς να δούμε το Private Key)
    signature = tpm.sign_data(message)
    
    # 2. Επαλήθευση (Όπως θα έκανε ο Server/Client)
    print(f"\nSignature (Hex): {signature.hex()[:64]}...")