import gymnasium as gym
from gymnasium import spaces
import numpy as np
import pandas as pd
from stable_baselines3 import PPO
import os
import hashlib
from stable_baselines3.common.vec_env import DummyVecEnv, VecNormalize
from typing import Tuple, Dict, Any

# --- PATH FIX: Βρίσκουμε τον φάκελο που βρίσκεται ΤΩΡΑ το script ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Συνθέτουμε τα σωστά μονοπάτια
DATA_FILENAME = os.path.join(SCRIPT_DIR, "data", "my_working_dataset.csv")
MODEL_SAVE_DIR = os.path.join(SCRIPT_DIR, "models")
MODEL_NAME = "ppo_hev"


class ProfessionalHybridEnv(gym.Env):
    """
    A gymnasium environment for HEV Energy Management.
    """
    def __init__(self, df: pd.DataFrame, temperature: float = 25.0):
        super(ProfessionalHybridEnv, self).__init__()
        self.df = df
        self.temperature = temperature
        self.current_step = 0
        self.soc = 60.0  # Initial State of Charge

        # Observation Space: [Speed, Acceleration, Power Demand, SOC]
        self.observation_space = spaces.Box(
            low=-np.inf, high=np.inf, shape=(4,), dtype=np.float32
        )

        # Action Space: [Engine Usage Ratio] (0.0 = Pure EV, 1.0 = Pure Engine)
        self.action_space = spaces.Box(
            low=0.0, high=1.0, shape=(1,), dtype=np.float32
        )

    def reset(self, seed=None, options=None) -> Tuple[np.ndarray, Dict]:
        super().reset(seed=seed)
        self.current_step = 0
        self.soc = 60.0
        return self._get_obs(), {}

    def _get_obs(self) -> np.ndarray:
        if self.current_step >= len(self.df):
            self.current_step = len(self.df) - 1
            
        row = self.df.iloc[self.current_step]

        eng_pwr = row.get('Engine Power (kW)', 0)
        reg_pwr = row.get('Regenerative Braking Power (kW)', 0)
        power_demand = eng_pwr - reg_pwr

        obs = np.array([
            row.get('Speed (km/h)', 0),
            row.get('Acceleration (m/s²)', 0),
            power_demand,
            self.soc
        ], dtype=np.float32)
        return obs

    def step(self, action: np.ndarray) -> Tuple[np.ndarray, float, bool, bool, Dict]:
        u_engine = float(np.clip(action[0], 0.0, 1.0))
        
        # Safety check for end of dataset
        if self.current_step >= len(self.df) - 1:
            return self._get_obs(), 0.0, True, False, {}

        row = self.df.iloc[self.current_step]

        # Environmental Factors
        if self.temperature < 10:
            temp_factor = 1.2  # Cold: Efficiency drop
        elif self.temperature > 30:
            temp_factor = 1.1  # Hot: HVAC load
        else:
            temp_factor = 1.0  # Optimal

        eng_pwr = row.get('Engine Power (kW)', 0)
        reg_pwr = row.get('Regenerative Braking Power (kW)', 0)
        power_demand = eng_pwr - reg_pwr
        
        fuel_consumption = 0.0
        
        # Hybrid Energy Logic
        if power_demand <= 0:
            # Regenerative Braking (Charging)
            battery_power = power_demand
            self.soc -= (battery_power * 0.001 * (1.0 / temp_factor))
        else:
            # Power Delivery
            engine_power = power_demand * u_engine
            battery_power = power_demand * (1.0 - u_engine)
            
            if engine_power > 0:
                fuel_consumption = (engine_power * 0.00025) 
            
            self.soc -= (battery_power * 0.001 * temp_factor)
            
        self.soc = np.clip(self.soc, 0.0, 100.0)
        
        # Reward Calculation
        reward = 0.0
        reward -= fuel_consumption * 10.0
      
        # Constraints Penalties
        if self.soc < 30: 
            reward -= 1.0 * (30 - self.soc)
        elif self.soc > 90: 
            reward -= 1.0 * (self.soc - 90)
            
        self.current_step += 1
        terminated = self.current_step >= len(self.df) - 1
        truncated = False
        
        info = {"fuel": fuel_consumption, "soc": self.soc}
        
        return self._get_obs(), reward, terminated, truncated, info


def generate_model_hash(filepath: str) -> str:
    """
    SECURITY: Generates a SHA-256 hash of the trained model file.
    This hash should be used by the loading mechanism to verify integrity.
    """
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def train_ppo(steps=200000, lr=0.0003, traffic='normal'):
    print(f"\n[INFO] Starting Training Session")
    print(f"[INFO] Configuration -> Steps: {steps}, LR: {lr}")

    if not os.path.exists(DATA_FILENAME):
        print(f"[ERROR] Dataset not found: {DATA_FILENAME}")
        return

    print("[INFO] Loading dataset...")
    df = pd.read_csv(DATA_FILENAME)
    df.columns = df.columns.str.strip() 

    if 'Regenerative Braking Power (kW)' not in df.columns:
         df['Regenerative Braking Power (kW)'] = 0.0

    # Environment Setup
    env = DummyVecEnv([lambda: ProfessionalHybridEnv(df)])
    env = VecNormalize(env, norm_obs=True, norm_reward=True, clip_obs=10.)

    # Ensure model directory exists
    os.makedirs(MODEL_SAVE_DIR, exist_ok=True)
    save_path = os.path.join(MODEL_SAVE_DIR, MODEL_NAME)

    print("[INFO] Initializing PPO Agent...")
    model = PPO("MlpPolicy", env, verbose=1, learning_rate=lr)
    
    print("[INFO] Training started...")
    model.learn(total_timesteps=steps)
    
    # Save Model
    model.save(save_path)
    env.save(f"{save_path}_vecnormalize.pkl")
    print(f"[INFO] Model saved at: {save_path}.zip")

    # --- SECURITY STEP: SIGN THE MODEL ---
    # Δημιουργούμε το "ψηφιακό αποτύπωμα" του μοντέλου
    final_model_path = f"{save_path}.zip"
    if os.path.exists(final_model_path):
        model_hash = generate_model_hash(final_model_path)
        hash_file = f"{save_path}.sha256"
        
        with open(hash_file, "w") as f:
            f.write(model_hash)
            
        print(f"[SECURITY] Model Hash generated: {model_hash}")
        print(f"[SECURITY] Hash saved to: {hash_file}")
        print("[SECURITY] Use this hash to verify integrity before loading.")
    else:
        print("[WARN] Could not find model file to generate hash.")

    print(f"[INFO] Training Sequence Completed Successfully.")


if __name__ == "__main__":
    train_ppo()