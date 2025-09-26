import pandas as pd
import numpy as np
from phishing_env import PhishingInboxEnv
from stable_baselines3 import DQN
from stable_baselines3.common.monitor import Monitor
from stable_baselines3.common.vec_env import DummyVecEnv

# -----------------------------
# 1️⃣ Load synthetic phishing dataset
# -----------------------------
df = pd.read_csv("synthetic_phishing_dataset.csv")
emails = df.to_dict(orient="records")

# -----------------------------
# 2️⃣ Create environment
# -----------------------------
def make_env():
    env = PhishingInboxEnv(emails)
    env = Monitor(env)  # logs cumulative reward per episode
    return env

env = DummyVecEnv([make_env])

# -----------------------------
# 3️⃣ Create DQN agent with optimized hyperparameters
# -----------------------------
model = DQN(
    "MlpPolicy",
    env,
    learning_rate=0.001,
    buffer_size=10000,
    batch_size=64,
    gamma=0.99,
    exploration_fraction=0.4,
    exploration_final_eps=0.05,
    target_update_interval=200,
    verbose=1
)

# -----------------------------
# 4️⃣ Train the agent
# -----------------------------
print("Starting training...")
model.learn(total_timesteps=50000, log_interval=10)
print("Training completed!")

# -----------------------------
# 5️⃣ Test the agent (without printing emails)
# -----------------------------
test_env = PhishingInboxEnv(emails)
obs, info = test_env.reset()
done = False
total_reward = 0
success_count = 0
total_emails = 0

while not done:
    action, _states = model.predict(obs)
    obs, reward, terminated, truncated, info = test_env.step(action)
    done = terminated or truncated
    total_reward += reward
    total_emails += 1
    if reward > 0:
        success_count += 1  # count emails successfully fooled

success_rate = success_count / total_emails * 100

print(f"\nEpisode finished!")
print(f"Total reward: {total_reward}")
print(f"Total emails: {total_emails}")
print(f"Success rate: {success_rate:.2f}%")

model.save("dqn_phishing_agent")  # saves to dqn_phishing_agent.zip
print("Model saved as dqn_phishing_agent.zip")
