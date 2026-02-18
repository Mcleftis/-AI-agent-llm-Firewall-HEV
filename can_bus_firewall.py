import time
import logging
import os
import secrets
import struct  # <--- ΑΠΑΡΑΙΤΗΤΟ για Binary Packing
from typing import Dict
from dotenv import load_dotenv

import rust_can_firewall 

load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class CANBusFirewall:

    def __init__(self, rate_limit: int = 100, burst_limit: int = 10) -> None:
        self.auth_token: str = os.getenv("CAN_AUTH_TOKEN", "DEFAULT_SECURE_TOKEN")
        self.blocked_ids: set = set()
        
        # Token Bucket State
        self.rate_limit = rate_limit  
        self.burst_limit = burst_limit 
        self.buckets: Dict[int, Dict[str, float]] = {}

    def verify_token(self, input_token: str) -> bool:
        if not input_token: return False
        if secrets.compare_digest(input_token, self.auth_token):
            return True
        logging.critical("ACCESS DENIED: Auth Failed.")
        return False

    def _check_rate_limit(self, packet_id: int) -> bool:
        current_time = time.time()
        if packet_id not in self.buckets:
            self.buckets[packet_id] = {'tokens': self.burst_limit, 'last_check': current_time}
        
        bucket = self.buckets[packet_id]
        time_passed = current_time - bucket['last_check']
        new_tokens = time_passed * self.rate_limit
        bucket['tokens'] = min(bucket['tokens'] + new_tokens, self.burst_limit)
        bucket['last_check'] = current_time

        if bucket['tokens'] >= 1.0:
            bucket['tokens'] -= 1.0
            return True
        return False

    def inspect_packet(self, packet_id: int, payload: bytes) -> bool:
        """
        Senior Level Inspection:
        1. Static Blacklist
        2. DoS Protection (Token Bucket)
        3. Stateful Inspection (Rust: Freshness + Physics)
        """
        # 1. Blocked List
        if packet_id in self.blocked_ids:
            return False

        # 2. DoS Check
        if not self._check_rate_limit(packet_id):
            logging.error(f"DoS ATTACK: ID {hex(packet_id)} rate limited.")
            return False

        # 3. Rust Stateful Inspection
        try:
            # Το payload πρέπει να είναι ήδη packed ως (Float + Int)
            is_safe = rust_can_firewall.inspect_packet(packet_id, payload)
            
            if not is_safe:
                # Αν η Rust πει όχι, σημαίνει Replay ή Physics violation
                logging.warning(f"SEC ALERT: ID {hex(packet_id)} blocked by Stateful Inspection (Replay/Spoofing).")
                return False
                
        except Exception as e:
            logging.error(f"FIREWALL ERROR: {e}")
            return False

        return True

    # --- ΒΟΗΘΗΤΙΚΗ ΣΥΝΑΡΤΗΣΗ ΓΙΑ ΤΟΝ "ΑΠΟΣΤΟΛΕΑ" ---
    def create_valid_packet(self, value: float, counter: int) -> bytes:
        """
        Δημιουργεί ένα έγκυρο Secure CAN Frame (8 bytes).
        Format: [Value (float, 4 bytes)] + [Counter (u32, 4 bytes)]
        """
        # '<fI' σημαίνει: Little Endian, float, unsigned int
        return struct.pack('<fI', value, counter)