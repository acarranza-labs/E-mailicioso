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

Install dependencies
pip install -r requirements.txt

Run application
python3 emailicioso.py

### 🖥️ Usage Guide
1. Load a .eml file

Go to File → Open EML, or drag & drop a file.

2. Navigate through analysis sections

Headers: inspect routing and metadata

Body: preview HTML/text

URLs: extracted links with intelligence results

Reputation: Talos / URLVoid / X-Force checks

Screenshots: automatic captures of URLs

3. Export investigation report

Use Export → Generate Report to output:


Perfect for incident response documentation.

### 📂 Project Structure
E-mailicioso/
├── emailicioso.py           # Main UI
├── core/
│   ├── parser.py            # Header + body parsing logic
│   ├── url_extractor.py     # URL extraction engine
│   ├── osint.py             # Talos, URLVoid & X-Force API handlers
│       └── screenshot.py    # Headless screenshot system
│   └── report.py            # Evidence generation
├── ui/
│   ├── main_window.glade    # GTK layout
│   └── icons/
├── reports/
├── requirements.txt
└── README.md

🔍 Example: Analyze a Simple Event in Python
from core.parser import parse_eml
from core.url_extractor import extract_urls
from core.osint import check_url_reputation

# Load EML
email_data = parse_eml("sample.eml")

# Extract URLs
urls = extract_urls(email_data.body_html)

# Check reputation
for url in urls:
    rep = check_url_reputation(url)
    print(url, rep)

### 🗺️ Roadmap

 Add VirusTotal integration

 Add hybrid ML-based phishing classifier

 Batch processing for multiple EML files

 Dark mode for GTK UI

 Build Windows/macOS/Linux executables

 Add plugin system for custom OSINT modules

### 🤝 Contributing

Pull requests and feature proposals are welcome.
You can also open Issues for bugs or suggestions.

