# SAP Honeypot 🍯

> **A specialized deception engineering tool mimicking SAP NetWeaver login interfaces to capture threat intelligence.**

![Python](https://img.shields.io/badge/Python-Flask-blue)
![Docker](https://img.shields.io/badge/Docker-Container-2496ED)
![Security](https://img.shields.io/badge/Focus-Deception_Tech-orange)

## 📖 Overview
**SAP Honeypot** is a lightweight deception system designed to:
1.  **Mimic** a legitimate SAP NetWeaver Logon screen.
2.  **Log** critical threat data (Source IP, User-Agent, Credentials).
3.  **Alert** security teams via a dashboard.

## ⚙️ Installation

### Local Setup
```bash
git clone https://github.com/osmankaankars/SAP-Honeypot.git
cd SAP-Honeypot
pip install -r requirements.txt
python app.py
```

Access the trap at: http://localhost:8080

**Dashboard**

View captured attacks at: http://localhost:8080/admin_dashboard

## 👨‍💻 Author
**Osman Kaan Kars**  
Cybersecurity Engineer | SAP Security Specialist  

**LinkedIn:** https://linkedin.com/in/osmankaankars  
**GitHub:** https://github.com/osmankaankars
