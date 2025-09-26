import csv
import random

# 10 quiz categories and 25 medium-level concepts/examples each
categories = {
    "Network Security": [
        ("HTTPS", "Hypertext Transfer Protocol Secure"),
        ("TLS", "Transport Layer Security"),
        ("Firewall", "Filters network traffic based on rules"),
        ("VPN", "Virtual Private Network"),
        ("Nmap", "Network scanning tool"),
        ("IDS", "Intrusion Detection System"),
        ("IPS", "Intrusion Prevention System"),
        ("DNS", "Resolves domain names to IPs"),
        ("DMZ", "Network segment exposed to untrusted networks"),
        ("DDoS", "Overwhelming a host with traffic"),
        ("NAT", "Translates private IPs to public IPs"),
        ("SCP", "Secure file copy over SSH"),
        ("SNMP", "Simple Network Management Protocol"),
        ("OSI Layer 3", "Network layer of OSI model"),
        ("SSH", "Secure shell for remote login"),
        ("DHCP", "Assigns dynamic IP addresses"),
        ("Wireshark", "Packet capture and analysis tool"),
        ("SSL", "Secure Sockets Layer"),
        ("UDP", "User Datagram Protocol"),
        ("ARP", "Address Resolution Protocol"),
        ("Phishing", "Tricking users to reveal data"),
        ("Least Privilege", "Granting only necessary permissions"),
        ("Segmentation", "Dividing network into zones"),
        ("ACL", "Access Control List for filtering"),
        ("RSA", "Asymmetric encryption algorithm")
    ],
    "Cryptography": [
        ("AES", "Advanced Encryption Standard"),
        ("RSA", "Rivest–Shamir–Adleman algorithm"),
        ("ECC", "Elliptic Curve Cryptography"),
        ("SHA-256", "Secure Hash Algorithm 256-bit"),
        ("MD5", "Message Digest 5 hash"),
        ("Diffie-Hellman", "Key exchange protocol"),
        ("Digital Signature", "Authenticates message origin"),
        ("Hash Function", "Maps data to fixed length digest"),
        ("Symmetric Encryption", "Same key to encrypt/decrypt"),
        ("Asymmetric Encryption", "Public/private key pair"),
        ("Salt", "Random data added to hash inputs"),
        ("Nonce", "Number used once in crypto"),
        ("PKI", "Public Key Infrastructure"),
        ("HMAC", "Hash-based Message Authentication Code"),
        ("PGP", "Pretty Good Privacy"),
        ("Public Key", "Key that can be widely shared"),
        ("Private Key", "Secret key kept by owner"),
        ("TLS Handshake", "Negotiates encryption parameters"),
        ("Block Cipher", "Encrypts fixed–size data blocks"),
        ("Stream Cipher", "Encrypts data bit-by-bit"),
        ("One-Time Pad", "Unbreakable when used correctly"),
        ("Steganography", "Hiding data inside other data"),
        ("Certificate Authority", "Issues digital certificates"),
        ("CRL", "Certificate Revocation List"),
        ("Cryptanalysis", "Breaking or analyzing ciphers")
    ],
    "Malware": [
        ("Virus", "Self-replicating code attaching to programs"),
        ("Worm", "Standalone self-replicating malware"),
        ("Trojan", "Malware disguised as legitimate software"),
        ("Ransomware", "Encrypts files for ransom"),
        ("Spyware", "Gathers user data without consent"),
        ("Adware", "Displays unwanted advertisements"),
        ("Rootkit", "Hides malicious activities"),
        ("Bootkit", "Infects the boot sector"),
        ("Logic Bomb", "Triggers malicious action on condition"),
        ("Keylogger", "Records keystrokes"),
        ("Polymorphic Malware", "Changes code to evade detection"),
        ("Macro Virus", "Spreads via document macros"),
        ("Backdoor", "Bypasses normal authentication"),
        ("Dropper", "Installs other malware"),
        ("Botnet", "Network of compromised machines"),
        ("Drive-by Download", "Automatic malware download"),
        ("Fileless Malware", "Resides in memory only"),
        ("Firmware Malware", "Infects device firmware"),
        ("Phishing", "Email-based credential theft"),
        ("Logic Bomb", "Conditional malicious code"),
        ("Remote Access Trojan", "Gives attacker remote control"),
        ("Wiper", "Permanently deletes data"),
        ("Polymorphic Virus", "Alters code on each infection"),
        ("Malvertising", "Infected online ads"),
        ("Cross-Site Scripting", "Injects script into web pages")
    ],
    "Ethical Hacking": [
        ("Footprinting", "Gathering target info"),
        ("Scanning", "Probing targets for open ports"),
        ("Enumeration", "Extracting user and resource info"),
        ("Vulnerability Assessment", "Identifying vulnerabilities"),
        ("Penetration Testing", "Exploiting found vulnerabilities"),
        ("Social Engineering", "Manipulating people"),
        ("Phishing Test", "Simulated phishing attack"),
        ("Password Cracking", "Brute forcing passwords"),
        ("Metasploit", "Exploitation framework"),
        ("Nmap", "Port scanning tool"),
        ("SQL Injection Test", "Testing for DB injection"),
        ("Buffer Overflow Test", "Testing memory boundaries"),
        ("Privilege Escalation", "Gaining higher rights"),
        ("Reverse Engineering", "Analyzing binaries"),
        ("Exploit Development", "Coding new exploits"),
        ("XSS Testing", "Testing for script injection"),
        ("Fuzzing", "Random input vulnerability test"),
        ("Wireless Testing", "Assessing Wi-Fi security"),
        ("Vulnerability Reporting", "Documenting findings"),
        ("Security Audit", "Comprehensive security review"),
        ("Policy Review", "Evaluating security policies"),
        ("Risk Assessment", "Estimating impact/likelihood"),
        ("Mitigation Strategies", "Reducing identified risks"),
        ("OSINT", "Open-source intelligence gathering"),
        ("WAR Driving", "Mapping Wi-Fi networks")
    ],
    "Digital Forensics": [
        ("Chain of Custody", "Documenting evidence handling"),
        ("Disk Imaging", "Creating bit-for-bit copies"),
        ("Write Blocker", "Prevents disk modifications"),
        ("File Carving", "Recovering files from fragments"),
        ("Timeline Analysis", "Reconstructing event order"),
        ("Memory Forensics", "Analyzing RAM contents"),
        ("Live Acquisition", "Collecting data from running systems"),
        ("Hash Analysis", "Verifying data integrity"),
        ("Artifact Extraction", "Pulling useful data snippets"),
        ("Metadata Analysis", "Inspecting file metadata"),
        ("Log Analysis", "Reviewing system logs"),
        ("Email Header Analysis", "Tracing email origins"),
        ("Registry Analysis", "Windows registry investigation"),
        ("Network Forensics", "Capturing network traffic"),
        ("Cloud Forensics", "Investigating cloud artifacts"),
        ("Mobile Forensics", "Analyzing smartphones/tablets"),
        ("IoT Forensics", "Investigating smart device data"),
        ("Malware Forensics", "Dissecting malware code"),
        ("Timeline Reconstruction", "Building system timelines"),
        ("Drive Encryption Analysis", "Cracking encrypted drives"),
        ("Deleted File Recovery", "Restoring erased data"),
        ("Slack Space Analysis", "Investigating file slack"),
        ("File Signature Analysis", "Matching file headers"),
        ("RAM Dumping", "Capturing memory image"),
        ("Registry Hives", "Hex-level registry files")
    ],
    "Social Engineering": [
        ("Phishing", "Email-based data theft"),
        ("Pretexting", "Inventing fake scenarios"),
        ("Baiting", "Offering false incentives"),
        ("Tailgating", "Following authorized users"),
        ("Quid Pro Quo", "Offering service for info"),
        ("Spear Phishing", "Targeted phishing attack"),
        ("Vishing", "Voice-based phishing"),
        ("Smishing", "SMS-based phishing"),
        ("Impersonation", "Posing as someone else"),
        ("Dumpster Diving", "Searching trash for data"),
        ("Shoulder Surfing", "Observing keystrokes"),
        ("Scareware", "Fake threat pop-ups"),
        ("Watering Hole", "Compromising frequented sites"),
        ("Deepfake", "Synthetic media deception"),
        ("Trust Exploitation", "Using relationships"),
        ("Reciprocity Principle", "Giving to get"),
        ("Authority Principle", "Impersonating authority"),
        ("Scarcity Principle", "Urgent deadlines"),
        ("Consensus Principle", "“Everyone’s doing it”)"),
        ("Liking Principle", "Friendly approach"),
        ("Cognitive Bias", "Exploiting mental shortcuts"),
        ("Inoculation Theory", "Pre-warning defenses"),
        ("Emotional Manipulation", "Triggering feelings"),
        ("Social Media Profiling", "Mining public profiles"),
        ("Tailored Pretext", "Highly customized scenario")
    ],
    "Cloud Security": [
        ("IaaS", "Infrastructure as a Service"),
        ("PaaS", "Platform as a Service"),
        ("SaaS", "Software as a Service"),
        ("CASB", "Cloud Access Security Broker"),
        ("SSO", "Single Sign-On"),
        ("IAM", "Identity and Access Management"),
        ("Encryption at Rest", "Protecting stored data"),
        ("Encryption in Transit", "Protecting data in motion"),
        ("API Security", "Securing cloud APIs"),
        ("Container Security", "Protecting container workloads"),
        ("Microservices", "Small, modular services"),
        ("Shared Responsibility", "Division of security duties"),
        ("SOC", "Security Operations Center"),
        ("Compliance", "Meeting security standards"),
        ("DLP", "Data Loss Prevention"),
        ("MFA", "Multi-Factor Authentication"),
        ("KMS", "Key Management Service"),
        ("Tenant Isolation", "Separating customer data"),
        ("Virtual Network", "Cloud network segment"),
        ("Security Group", "Virtual firewall rules"),
        ("WAF", "Web Application Firewall"),
        ("Cloud Audit", "Reviewing cloud logs"),
        ("Credential Management", "Handling cloud credentials"),
        ("Secret Rotation", "Regular key turnover"),
        ("Zero Trust", "Never trust, always verify")
    ],
    "IoT Security": [
        ("Device Authentication", "Verifying device identity"),
        ("Firmware Updates", "Patching device software"),
        ("Secure Boot", "Validating firmware integrity"),
        ("Network Segmentation", "Isolating IoT networks"),
        ("Edge Security", "Protecting edge devices"),
        ("Default Credentials", "Weak out-of-box passwords"),
        ("MQTT Security", "Securing IoT messaging protocol"),
        ("CoAP Security", "Constrained Application Protocol"),
        ("Zigbee Encryption", "Securing Zigbee traffic"),
        ("Bluetooth LE Sec", "Bluetooth Low-Energy safety"),
        ("TLS on IoT", "Encrypting IoT comms"),
        ("OWASP IoT 10", "Top 10 IoT vulnerabilities"),
        ("Physical Tampering", "Protecting device access"),
        ("Side-Channel Attack", "Extracting keys via leaks"),
        ("Supply Chain Sec", "Securing components"),
        ("Sensor Spoofing", "Faking sensor data"),
        ("Data Encryption", "Encrypting IoT data"),
        ("Anomaly Detection", "Identifying abnormal behavior"),
        ("RTOS Security", "Protecting real-time OS"),
        ("Memory Protection", "Separating memory spaces"),
        ("Firmware Signing", "Digitally signing firmware"),
        ("Secure Provisioning", "Safe device onboarding"),
        ("OTA Updates", "Over-the-air patching"),
        ("Certificate Pinning", "Locking server certs"),
        ("Remote Attestation", "Verifying device state")
    ],
    "Software Vulnerabilities": [
        ("Buffer Overflow", "Exceeds memory buffer"),
        ("SQL Injection", "Injecting SQL commands"),
        ("XSS", "Cross-Site Scripting"),
        ("CSRF", "Cross-Site Request Forgery"),
        ("Directory Traversal", "Accessing restricted files"),
        ("Deserialization", "Untrusted object replay"),
        ("Command Injection", "OS command execution"),
        ("Race Condition", "Timing-based flaw"),
        ("Integer Overflow", "Exceeds integer limits"),
        ("Path Traversal", "File path manipulation"),
        ("Header Injection", "HTTP header tampering"),
        ("Open Redirect", "Unvalidated redirects"),
        ("Insecure Function", "Unsafe library calls"),
        ("Memory Leak", "Unreleased memory"),
        ("Format String", "Uncontrolled printf formats"),
        ("Heap Spray", "Inject code via heap"),
        ("Script Inclusion", "Loading remote scripts"),
        ("SSRF", "Server-Side Request Forgery"),
        ("Clickjacking", "UI redressing attack"),
        ("CORS Misconfig", "Cross-origin missetup"),
        ("Default Password", "Unchanged credentials"),
        ("Debug Mode", "Verbose debugging left on"),
        ("Log Injection", "Tampering log entries"),
        ("Weak RNG", "Predictable random numbers"),
        ("Env Variable Leak", "Stolen server config")
    ],
    "Access Control": [
        ("RBAC", "Role-Based Access Control"),
        ("ABAC", "Attribute-Based Access Control"),
        ("MAC", "Mandatory Access Control"),
        ("DAC", "Discretionary Access Control"),
        ("Least Privilege", "Minimal permission principle"),
        ("SoD", "Segregation of Duties"),
        ("MFA", "Multi-Factor Authentication"),
        ("SSO", "Single Sign-On"),
        ("OAuth", "Authorization framework"),
        ("LDAP", "Directory access protocol"),
        ("SAML", "Security Assertion Markup Lang"),
        ("Kerberos", "Ticket-based authentication"),
        ("ACL", "Access Control List"),
        ("Group Policy", "Windows policy management"),
        ("Access Token", "Auth token for sessions"),
        ("Session Timeout", "Auto-logout timer"),
        ("Time-of-Day Restriction", "Time-based access"),
        ("Geofencing", "Location-based control"),
        ("Context-Based", "Adaptive access decisions"),
        ("PAM", "Privileged Access Management"),
        ("Password Policy", "Rules for passwords"),
        ("Account Lockout", "Thwart brute-force attempts"),
        ("Biometrics", "Fingerprint or retina scan"),
        ("Certificate Auth", "X.509 certificate login"),
        ("Delegated Access", "Temporary elevated rights")
    ]
}

def make_question(concept, definition):
    """
    If concept is an acronym, ask what it stands for.
    Otherwise, ask for its primary function/definition.
    """
    if concept.isupper() or any(c.isdigit() for c in concept):
        q = f"What does {concept} stand for?"
        correct = definition
    else:
        q = f"What is the primary purpose of {concept}?"
        correct = definition
    return q, correct

def make_options(correct, pool):
    """
    Build 4 options: the correct one plus 3 random others from pool.
    Ensure no duplicates.
    """
    distractors = random.sample([d for d in pool if d != correct], 3)
    opts = [correct] + distractors
    random.shuffle(opts)
    return opts

# Flatten all definitions into one pool for distractors
all_defs = [definition for cat in categories.values() for _, definition in cat]

with open("quiz_dataset.csv", "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["category","question","option1","option2","option3","option4","answer","difficult"])

    for cat, items in categories.items():
        for concept, definition in items:
            question, correct_answer = make_question(concept, definition)
            opts = make_options(correct_answer, all_defs)
            writer.writerow([cat, question, *opts, correct_answer, "medium"])

print("Generated quiz_dataset.csv with {} questions.".format(
    sum(len(v) for v in categories.values())
))