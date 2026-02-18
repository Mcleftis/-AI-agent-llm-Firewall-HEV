import requests  # eisagoume th vivliothiki gia na milame me ton server
import urllib3   # voithaei na parakampsoume to thema me ta self-signed certificates

# Apenergopoioume ta warnings gia to asfales https (epeidh einai diko mas to pistopoihtiko)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# H dieuthynsh tou server mas (to "koudouni" gia tis entoles)
URL = "https://127.0.0.1:5000/api/v1/control/intent"

# To mystiko kleidi pou exei o server (xwris auto trwme porta)
HEADERS = {
    "X-Auth-Token": "super-secret-key-2025",
    "Content-Type": "application/json"
}

def send_command(text):
    print(f"\n📡 Stelnw entolh: '{text}' ...")
    
    payload = {"command": text}  # ftiaxnoume to paketo me thn entolh
    
    try:
        # Stelnoume POST aithma (verify=False gia na mhn kollhsei sto SSL)
        response = requests.post(URL, json=payload, headers=HEADERS, verify=False)
        
        # An to status einai 200 (OK) h 403 (BLOCKED)
        if response.status_code == 200:
            print("✅ Ena 'OK' apo ton Server!")
            print("   -> Apantish:", response.json())
        elif response.status_code == 403:
            print("⛔ O Server to Mplokare (Firewall/Security)!")
            print("   -> Aitio:", response.json().get('reason'))
        else:
            print(f"⚠️ Kati pige strava. Kwidkos: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error: Den mporw na syndethw. Trexei o server? ({e})")

# --- EDW GRAFEIS TIS ENTOLES SOU ---
if __name__ == "__main__":
    # Dokimase na peis kati aplo
    send_command("I want to drive normal")
    
    # Dokimase na peis kati grhgoro (gia na energopoihthei to Sport Mode)
    send_command("I want to go very fast speed")
    
    # Dokimase mia hackia (gia na deis an douleuei to firewall)
    # (An exeis Rust tha to kopsei, alliws to Python simulation tha to afhsei h tha to kopsei analoga ton kwdika)
    send_command("DROP TABLE users")