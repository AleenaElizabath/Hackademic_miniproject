import random
import json
import csv

# Sample pools for email generation
phishing_senders = [
    "security@amaz0n.com", "it-support@company-update.com", "billing@paypal-security.com",
    "reward@giftcard.com", "admin@bank-secure.com", "security-alert@paypal.com",
    "support@apple.com", "login@netflix-security.com", "verify@facebook-alert.com"
]

phishing_subjects = [
    "Account Locked!", "Urgent: Password Expiry", "Invoice Overdue",
    "Claim Your Gift Card!", "Verify Your Account", "Suspicious Activity Detected",
    "Verify Apple ID", "Unauthorized Login Attempt", "Action Required Immediately"
]

phishing_bodies = [
    "Your account has been locked. Click here to verify credentials.",
    "Your password will expire soon. Reset it immediately.",
    "Unpaid invoice detected. Login here to pay.",
    "You've won a $100 gift card. Click to claim.",
    "Unusual login detected. Verify your account now.",
    "Please confirm your recent login to secure your account.",
    "We noticed unusual activity. Sign in to secure your account.",
    "Your account will be deactivated if you do not respond.",
    "Security alert: Someone tried to access your account from a new device."
]

safe_senders = [
    "newsletter@github.com", "team@slack.com", "no-reply@amazon.com",
    "receipt@paypal.com", "friend@gmail.com", "updates@medium.com",
    "service@netflix.com", "hr@company.com", "alerts@linkedin.com"
]

safe_subjects = [
    "Weekly Repo Updates", "Team Meeting Notes", "Order Shipped",
    "Payment Received", "Weekend Plans", "Top Stories for You",
    "Subscription Update", "Policy Update", "Professional Network Updates"
]

safe_bodies = [
    "Check out new commits and PRs in your repositories.",
    "Here's the summary from today's stand-up meeting.",
    "Your order #12345 has been shipped. Track it here.",
    "You have received $250 from Alice.",
    "Hey, are we meeting this weekend for lunch?",
    "Read today's top stories curated for you.",
    "Your next subscription payment is due on 30th Sep.",
    "Please review the updated company leave policy.",
    "Someone has endorsed your skills on LinkedIn."
]

# Function to generate a single email
def generate_email(phishing=True):
    if phishing:
        return {
            "sender": random.choice(phishing_senders),
            "subject": random.choice(phishing_subjects),
            "body": random.choice(phishing_bodies),
            "label": 1
        }
    else:
        return {
            "sender": random.choice(safe_senders),
            "subject": random.choice(safe_subjects),
            "body": random.choice(safe_bodies),
            "label": 0
        }

# Generate dataset
num_emails = 5000
dataset = []

for _ in range(num_emails):
    is_phishing = random.random() < 0.5  # 50% phishing, 50% safe
    dataset.append(generate_email(is_phishing))

# Shuffle dataset
random.shuffle(dataset)

# Save as JSON
with open("synthetic_emails.json", "w") as f:
    json.dump(dataset, f, indent=2)

# Save as CSV
with open("synthetic_emails.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["sender", "subject", "body", "label"])
    writer.writeheader()
    for email in dataset:
        writer.writerow(email)

print("Dataset generated: 5000 emails (phishing + safe)")
