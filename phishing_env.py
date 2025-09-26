import random
import gymnasium as gym
from gymnasium import spaces
import numpy as np

class PhishingInboxEnv(gym.Env):
    """
    Custom RL Environment for Phishing Inbox Game.
    State: current email features
    Action: 0 = mark as Legit, 1 = mark as Phish
    Reward: +1 if agent successfully tricks player, -1 if detected
    """
    metadata = {'render.modes': ['human']}

    def __init__(self, emails):
        super(PhishingInboxEnv, self).__init__()

        self.emails = emails
        self.current_idx = 0

        # Action space: 0 = Legit, 1 = Phish
        self.action_space = spaces.Discrete(2)

        # Observation space: simplified numerical features [sender_type, subject_type, body_type]
        # 0 = legit, 1 = phish
        self.observation_space = spaces.MultiBinary(3)

    def reset(self, *, seed=None, options=None):
        # Gymnasium expects this signature
        super().reset(seed=seed)  # optional, ensures seeding works
        self.current_idx = 0
        obs = self._get_observation()
        info = {}  # Gymnasium requires reset to return (obs, info)
        return obs, info


    def _get_observation(self):
        email = self.emails[self.current_idx]
        sender_type = 1 if "@" in email['sender'] and "secure-login" in email['sender'] else 0
        subject_type = 1 if any(word in email['subject'].lower() for word in ["verify", "urgent", "prize", "suspended"]) else 0
        body_type = 1 if any(word in email['body'].lower() for word in ["click", "update", "claim", "suspended"]) else 0
        return np.array([sender_type, subject_type, body_type], dtype=np.int8)

    def step(self, action):
        email = self.emails[self.current_idx]
        terminated = False
        truncated = False

        correct_label = 1 if email['label'] == "phish" else 0

        if action == correct_label:
            reward = -1
        else:
            reward = 1

        self.current_idx += 1
        if self.current_idx >= len(self.emails):
            terminated = True
            truncated = False

        obs = self._get_observation() if not terminated else np.zeros(3)
        return obs, reward, terminated, truncated, {}


    def render(self, mode='human'):
        if self.current_idx < len(self.emails):
            email = self.emails[self.current_idx]
            print(f"Email {self.current_idx+1}: {email['subject']} | {email['sender']}")
        else:
            print("End of inbox.")
