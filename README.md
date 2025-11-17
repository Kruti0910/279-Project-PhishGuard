# 🛡️ Smart Phishing Detection System

## 🚀 Overview
The **Smart Phishing Detection System** is a Python-based application built to detect potential phishing emails through advanced email header and metadata analysis.  
It combines heuristic rules, sender validation, and routing path consistency checks to identify fraudulent messages with high accuracy.

This project is ideal for cybersecurity students, researchers, or professionals exploring how metadata-based detection can be used to identify suspicious email patterns.  
It supports `.eml`, `.msg`, and `.txt` formats and can analyze single or multiple emails efficiently.

---

## ✨ Features
- 📨 **Multi-format email support** — Works with `.eml`, `.msg`, and plain text files  
- 🧩 **Comprehensive header analysis** — Extracts, parses, and validates critical headers (*From*, *Reply-To*, *Received*, *Message-ID*, etc.)  
- ⚙️ **Heuristic rule-based detection** — Applies a combination of rules to identify spoofed or misconfigured email headers  
- 📊 **Detailed results** — Displays suspicious indicators, detection confidence, and verdict  
- 💻 **Command-line interface** — Simple CLI that supports both single-file and directory-level processing  

---

## ⚙️ Installation

```bash
# Clone this repository
git clone <your-repository-url>
cd 279-Project-PhishGuard

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate   # macOS / Linux
# OR
.\.venv\Scripts\activate    # Windows

# Install dependencies
pip install -r requirements.txt
