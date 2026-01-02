# 📧 E-mailicioso

**Portable Email Forensic Toolkit** - Analyze suspicious emails without the cloud.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![PySide6](https://img.shields.io/badge/GUI-PySide6-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 📨 **Header Analysis** | Full header inspection with raw view |
| 📝 **Body Rendering** | Text and HTML preview with inline images |
| 🛡️ **Security Check** | SPF/DKIM/DMARC pass/fail indicators |
| 🧲 **IOC Extraction** | IPs, domains, attachment hashes (MD5/SHA256) |
| 🔗 **URL Intelligence** | Detect obfuscated/redirect URLs |
| 🌐 **Reputation Check** | URLVoid integration for domain analysis |
| 🖼️ **Screenshot Capture** | Capture individual URLs as evidence |
| 📎 **Attachments** | View and save email attachments |
| 📄 **Export Report** | Generate HTML forensic reports |

### UX Features
- 🖱️ Drag & Drop `.eml` files
- 📖 Recent files history
- 🌙/☀️ Dark/Light theme toggle

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/E-mailicioso.git
cd E-mailicioso

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Install Playwright browser (for screenshots)
python -m playwright install chromium
```

---

## 🎮 Usage

```bash
python main.py
```

1. **Open an EML file** - Drag & drop or use File → Open
2. **Explore tabs** - Headers, Body, Security, IOCs, URLs, etc.
3. **Export report** - File → Export Report (HTML)

---

## 📁 Project Structure

```
E-mailicioso/
├── main.py              # Entry point
├── core/
│   ├── eml_parser.py    # Robust EML parsing
│   ├── url_extractor.py # URL extraction from text/HTML
│   ├── url_decoder.py   # Obfuscated URL detection
│   ├── security_analysis.py # SPF/DKIM/DMARC + IOCs
│   ├── reputation.py    # URLVoid API integration
│   ├── screenshots.py   # Playwright-based captures
│   ├── cache.py         # SQLite reputation cache
│   ├── report_generator.py # HTML report export
│   └── utils.py         # Helper functions
├── ui/
│   ├── main_window.py   # Main GUI window
│   ├── workers.py       # Background thread workers
│   └── styles.py        # Dark theme configuration
├── evidence/            # Screenshot output directory
└── requirements.txt
```

---

## 📋 Requirements

- Python 3.10+
- PySide6
- Playwright
- BeautifulSoup4
- tldextract
- requests

---

## 📸 Screenshots

*Coming soon*

---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first.

---

## 📜 License

[MIT](LICENSE)

---

## ⚠️ Disclaimer

This tool is intended for **legitimate security research and incident response** purposes only. Always ensure you have proper authorization before analyzing emails that don't belong to you.
