import pandas as pd
import gymnasium as gym
from gymnasium import spaces
import numpy as np
from stable_baselines3 import PPO
import matplotlib.pyplot as plt


DATA_FILENAME = "data/my_working_dataset.csv"
MODEL_PATH = "final_hybrid_agent_model"


class ProfessionalHybridEnv(gym.Env):
    def __init__(self, df):
        super(ProfessionalHybridEnv, self).__init__()
        self.df = df
        self.current_step = 0
        self.soc = 60.0 
        self.observation_space = spaces.Box(low=-np.inf, high=np.inf, shape=(4,), dtype=np.float32)
        self.action_space = spaces.Box(low=0.0, high=1.0, shape=(1,), dtype=np.float32)

    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        self.current_step = 0
        self.soc = 60.0 
        return self._get_obs(), {}

    def _get_obs(self):
        row = self.df.iloc[self.current_step]
        
        eng_pwr = row.get('Engine Power (kW)', 0)
        reg_pwr = row.get('Regenerative Braking Power (kW)', 0)
        power_demand = eng_pwr - reg_pwr
        return np.array([row.get('Speed (km/h)', 0), row.get('Acceleration (m/s²)', 0), power_demand, self.soc], dtype=np.float32)

    def step(self, action):
        u_engine = float(action[0])
        row = self.df.iloc[self.current_step]
        eng_pwr = row.get('Engine Power (kW)', 0)
        reg_pwr = row.get('Regenerative Braking Power (kW)', 0)
        power_demand = eng_pwr - reg_pwr
        
        fuel_consumption = 0.0
        battery_power = 0.0
        
        if power_demand <= 0:
            battery_power = power_demand
            self.soc -= (battery_power * 0.7) / 100 
        else:
            engine_power = power_demand * u_engine
            battery_power = power_demand * (1.0 - u_engine)
            if engine_power > 0: fuel_consumption = (engine_power * 0.00025) 
            self.soc -= (battery_power * 0.05) 
            
        self.soc = np.clip(self.soc, 0, 100)
        self.current_step += 1
        terminated = self.current_step >= len(self.df) - 1
        
        return self._get_obs(), 0, terminated, False, {"fuel": fuel_consumption, "soc": self.soc}


if __name__ == "__main__":
    df = pd.read_csv(DATA_FILENAME)
    df.columns = df.columns.str.strip()
    
    env_ai = ProfessionalHybridEnv(df)
    env_dumb = ProfessionalHybridEnv(df)
    
    model = PPO.load(MODEL_PATH)
    

    history_ai_fuel = []
    history_dumb_fuel = []
    history_ai_soc = []
    
    steps = 1000
    

    obs, _ = env_ai.reset()
    cum_fuel = 0
    for _ in range(steps):
        action, _ = model.predict(obs)
        obs, _, done, _, info = env_ai.step(action)
        cum_fuel += info['fuel']
        history_ai_fuel.append(cum_fuel)
        history_ai_soc.append(info['soc'])
        if done: break
        

    obs, _ = env_dumb.reset()
    cum_fuel = 0
    for _ in range(steps):
        action = [1.0] 
        obs, _, done, _, info = env_dumb.step(action)
        cum_fuel += info['fuel']
        history_dumb_fuel.append(cum_fuel)
        if done: break


    plt.figure(figsize=(12, 6))
    

    plt.subplot(1, 2, 1)
    plt.plot(history_dumb_fuel, label='Conventional (Dumb)', color='red', linestyle='--')
    plt.plot(history_ai_fuel, label='AI Agent (PPO)', color='green', linewidth=2)
    plt.title('Cumulative Fuel Consumption')
    plt.xlabel('Time (seconds)')
    plt.ylabel('Fuel (Liters)')
    plt.legend()
    plt.grid(True)
    

    plt.subplot(1, 2, 2)
    plt.plot(history_ai_soc, label='AI Battery SOC', color='blue')
    plt.title('AI Battery Strategy (SOC)')
    plt.xlabel('Time (seconds)')
    plt.ylabel('SOC (%)')
    plt.axhline(y=20, color='r', linestyle=':', label='Min Limit')
    plt.axhline(y=90, color='r', linestyle=':', label='Max Limit')
    plt.legend()
    plt.grid(True)
    
    plt.tight_layout()

    plt.savefig("visualize_AI_agent.png") 
    print("Graph saved to visualize1_result.png")
    plt.close() #katharismos mnhmhs

    