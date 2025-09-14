# 🛡️ Python Antivirus Demo (YARA)

A fun and educational Python project to build your own antivirus using YARA rules!

![Optional GUI Screenshot](screenshot.png)

---

## 🎯 Project Overview

**Python Antivirus Demo (YARA)** is a lightweight antivirus engine built in Python.  
It uses **YARA rules** to detect malware, ransomware, RATs, and suspicious files.  
You can also monitor folders in **real-time** to catch threats immediately.

**Why it’s fun:**  
- Learn how antivirus software works under the hood.  
- Test files safely in a controlled environment.  
- Explore real-world malware detection rules.  
- Hands-on Python, GUI, and real-time monitoring experience.

---

## ⚡ Features

- ✅ **YARA-based scanning**: Detects threats using `.yar` or `.yara` rules.  
- ✅ **File & folder scanning**: Scan a single file or entire directories.  
- ✅ **Real-time monitoring (RTM)**: Monitor folders for new or modified files.  
- ✅ **Interactive GUI**: Simple, clean interface using Tkinter.  
- ✅ **Extensible rules**: Easily add your own YARA rules.

---

## 🛠️ Installation

**Clone the repository:**
```bash
git clone https://github.com/yourusername/python-antivirus-demo.git
cd python-antivirus-demo
```
**Create a virtual environment (optional but recommended):**
```bash
python -m venv venv
source venv/bin/activate    # Linux / macOS
venv\Scripts\activate       # Windows
```
**Install dependencies:**
```bash
pip install -r requirements.txt
```
Requirements include: yara-python, watchdog, tkinter (built-in with Python)

Add YARA rules: Place .yar or .yara files inside the rules/ folder.
You can download open-source rules from YARA-Rules GitHub
