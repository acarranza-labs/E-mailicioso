# E-mailicioso

E-mailicioso is a forensic email analysis toolkit built in **Python + PyGTK** for inspecting **.eml files** and extracting security-relevant information with speed and clarity.  
It is designed for **SOC analysts, cybersecurity students and threat researchers** who need a fast and reliable way to detect phishing, analyze suspicious emails and generate evidences for incident reports.

---

## ✨ Features

### 1. EML File Parsing
- Full header analysis (Return-Path, Message-ID, MIME, Received chain)
- Body extraction (plain text + HTML)
- Detection of anomalies and spoofing indicators

### 2. URL Extraction & Threat Intelligence
- Automatic extraction of URLs (including redirects and hidden links)
- Reputation lookups using:
  - **Talos Intelligence**
  - **URLVoid**
  - **IBM X-Force Exchange**
- Identification of:
  - Malicious domains  
  - Phishing infrastructure  
  - Suspicious parameters/tracking  

### 3. Sender & Domain Analysis
- WHOIS summary (age, registrar, country)
- MX lookup
- Quick SPF/DKIM heuristic validation
- IP reputation hints

### 4. Evidence Capture: Headless Browser Screenshots
- Fully automated screenshot of URLs using a **headless browser**
- Timestamped images for forensic chaining
- Ideal for SOC tickets and incident cases

### 5. Exportable Reports
Export forensic evidence in:
- **HTML** (human-readable)
- **Markdown** (perfect for SOC tickets)
- **JSON** (machine-readable for automation)

### 6. Modern Desktop UI (PyGTK)
- Clean interface  
- Tabs for Headers, Body, URLs, Threat Intelligence, Screenshots  
- Ready for dark/light themes

---

## 🧩 Tech Stack

| Area | Technology |
|------|------------|
| GUI | PyGTK |
| Email Parsing | `email`, `mailparser` |
| URL Extraction | `bs4`, regex, custom parser |
| OSINT APIs | Talos, URLVoid, IBM X-Force |
| Screenshot Engine | Playwright (recommended) |
| Packaging | PyInstaller (optional) |

---

## 🚀 Installation

### Clone repository
```bash
git clone https://github.com/acarranza-labs/E-mailicioso.git
cd E-mailicioso
