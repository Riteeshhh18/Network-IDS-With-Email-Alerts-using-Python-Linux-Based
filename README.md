# Network-IDS-With-Email-Alerts-using-Python-Linux-Based

# **📌 Network Intrusion Detection System (NIDS) using Python & tcpdump**

A lightweight Python-based real-time **Network Intrusion Detection System (NIDS)** for Ubuntu/Linux.
This system detects **port scan attempts**, especially **stealth SYN scans (Nmap -sS)**, by monitoring live network packets using `tcpdump`.

The script tracks repeated **TCP SYN packets** from the same IP within a short time window.
If an attacker sends too many connection attempts quickly (common during Nmap scans), the tool immediately:

✔ Prints a warning
✔ Sends an email alert
✔ Logs the attack source

This NIDS is simple, fast, and suitable for personal servers, small labs, or learning network security.

---

# **✨ Features**

* ⚡ **Real-time port scan detection**
* 🔍 Detects Nmap SYN scan & fast scan patterns
* 🧠 Tracks attacker IP behavior using sliding window
* 📬 Sends email alert when scan is detected
* 📡 Works with `tcpdump` for high-speed packet capture
* 🔐 No kernel modification required
* 🪶 Lightweight (runs on any Linux system)

---

# **🛠️ How It Works (Simple Explanation)**

This tool starts `tcpdump` in the background with this filter:

```
tcp[tcpflags] & tcp-syn != 0
```

➡ This captures **only SYN packets**, which are used to initiate TCP connections.

The script counts how many SYN packets each IP sends in **X seconds**.

If the count exceeds the threshold (e.g., 20 SYNs in 10 seconds), it assumes:

### ❗ A port scan is happening

(especially `nmap -sS -p-1000 <target>`)

Then it triggers an **alert email**, showing the attacker’s IP and sample packet.

---

# **📥 Installation (Ubuntu / Debian)**

### **1. Install tcpdump**

```bash
sudo apt update
sudo apt install tcpdump -y
```

### **2. Clone the GitHub Repository**

```bash
git clone https://github.com/yourusername/NIDS-Scan-Detector.git
cd NIDS-Scan-Detector
```

### **3. Install Python requirements**

This script uses only built-in Python modules.
No pip installs needed.

### **4. Make script executable**

```bash
chmod +x simple_scan_alert.py
```

---

# **⚙️ Configuration**

Edit the script to set:

* SMTP email ID
* App password
* Receiver email
* Scan threshold
* Network interface name (optional)

Example:

```python
SMTP_USER = "your_email@gmail.com"
SMTP_PASS = "your_gmail_app_password"
ALERT_TO  = "your_email@gmail.com"

THRESHOLD = 20   # SYN count trigger
WINDOW = 10      # seconds
```

---

# **🚀 Usage**

### **Run as root (required by tcpdump)**

```bash
sudo python3 simple_scan_alert.py
```

You will see live logs:

```
[12:01:33] SYN from 192.168.1.50 (count=3)
[12:01:33] SYN from 192.168.1.50 (count=6)
...
>>> Possible scan detected! Attacker IP: 192.168.1.50 (count=20)
[*] Email alert sent.
```

---

# **💻 Full Python Code (Included Below)**

```python
#!/usr/bin/env python3
"""
simple_scan_alert.py
Very small port-scan detector + email alert.
Requirements:
 - tcpdump installed (sudo apt install tcpdump)
 - Run as root (sudo)
Configure SMTP_USER, SMTP_PASS, ALERT_TO below.
"""

import subprocess, time, re, smtplib
from collections import defaultdict, deque
from email.mime.text import MIMEText

# ======= CONFIGURATION =======
TCPDUMP_CMD = "/usr/sbin/tcpdump"   # check with: which tcpdump
INTERFACE = ""                      # e.g., "eth0", or leave "" for auto
THRESHOLD = 20                      # SYN count to trigger alert
WINDOW = 10                         # time window in seconds
VERBOSE = True                      # print live logs

# Email alert (Gmail Example)
SMTP_USER = "your_email@gmail.com"
SMTP_PASS = "your_gmail_app_password"
ALERT_TO  = "your_email@gmail.com"
# ===================================

# Regex to extract source IP
IP_RE = re.compile(r"IP\s+(\d+\.\d+\.\d+\.\d+)\.")
state = defaultdict(lambda: deque())  # ip -> timestamps list


def send_email(subject, body):
    """Send an email alert."""
    if not SMTP_USER or not SMTP_PASS or not ALERT_TO:
        print("[!] Email not configured. Skipping email.")
        return False
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = SMTP_USER
        msg['To'] = ALERT_TO

        with smtplib.SMTP('smtp.gmail.com', 587, timeout=10) as s:
            s.ehlo()
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(SMTP_USER, [ALERT_TO], msg.as_string())

        print("[*] Email alert sent.")
        return True
    except Exception as e:
        print("[!] Failed to send email:", e)
        return False


def start_tcpdump():
    """Start tcpdump process with SYN filter."""
    iface = ["-i", INTERFACE] if INTERFACE else []
    cmd = [TCPDUMP_CMD] + iface + ["-n", "-l", "tcp[tcpflags] & tcp-syn != 0"]
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)


def main():
    print(f"[*] Scan detector running (THRESHOLD={THRESHOLD}, WINDOW={WINDOW}s)")
    p = start_tcpdump()

    if not p or not p.stdout:
        print("[!] Failed to start tcpdump. Run with sudo or check installation.")
        return

    try:
        while True:
            line = p.stdout.readline()
            if not line:
                time.sleep(0.1)
                continue

            match = IP_RE.search(line)
            if not match:
                continue

            src_ip = match.group(1)
            now = time.time()
            dq = state[src_ip]
            dq.append(now)

            # Remove timestamps older than WINDOW seconds
            while dq and dq[0] < now - WINDOW:
                dq.popleft()

            count = len(dq)
            if VERBOSE:
                print(f"[{time.strftime('%H:%M:%S')}] SYN from {src_ip} (count={count})")

            # Trigger alert
            if count >= THRESHOLD:
                message = (
                    f"Possible port scan detected from {src_ip}\n"
                    f"SYN Count: {count} in {WINDOW} seconds.\n"
                    f"Sample Packet:\n{line.strip()}"
                )
                print(f"\n>>> ALERT! Scan detected from {src_ip} ({count} SYNs)\n")
                send_email(f"Scan Detected from {src_ip}", message)

                # Reset state to avoid duplicate alerts
                state[src_ip].clear()

    except KeyboardInterrupt:
        print("\n[+] Exiting.")
        p.terminate()
        p.wait()


if __name__ == "__main__":
    main()
```

---

# **🧪 Testing With Nmap**

Use Nmap on any machine inside the same network:

### **SYN Scan**

```bash
nmap -sS -p-1000 <target_ip>
```

### **Fast Scan**

```bash
nmap -F <target_ip>
```

### **Full Port Scan**

```bash
nmap -p- <target_ip>
```

The script should trigger an alert when SYN traffic exceeds your threshold.

---

# **📊 Example Email Alert**

```
Subject: Scan detected from 192.168.1.50

Detected possible port scan:
IP: 192.168.1.50
SYN Count: 23 in 10 seconds

Example tcpdump packet:
IP 192.168.1.50.51032 > 192.168.1.10.22: Flags [S], seq 123456789, win 64240
```

---

# **📅 Future Scope**

* 🚧 Auto-block attacker using `iptables`
* 📈 Save attack logs to a file or database
* 🖥️ Create a web dashboard to view alerts
* 🤖 Use ML to classify scan patterns
* 🛡️ Detect brute-force login attempts
* 🔁 Add systemd service for auto-start on boot

---



✅ A **systemd service file** so this NIDS runs automatically at startup
✅ A **logo** for your repository

Just tell me!
