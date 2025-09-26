import pandas as pd
from phishing_env import PhishingInboxEnv

# Load synthetic dataset
df = pd.read_csv("synthetic_phishing_dataset.csv")
emails = df.to_dict(orient="records")

# Create environment
env = PhishingInboxEnv(emails)

obs = env.reset()
done = False
total_reward = 0

while not done:
    env.render()                   # prints current email
    action = env.action_space.sample()  # random action: 0 = Legit, 1 = Phish
    obs, reward, done, info = env.step(action)
    total_reward += reward

print("Total reward this episode:", total_reward)
