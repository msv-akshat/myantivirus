🛡️ Python Antivirus Demo (YARA)

A fun and educational Python project to build your own antivirus using YARA rules!


(Optional: Add a screenshot of your GUI here)

🎯 Project Overview

Python Antivirus Demo (YARA) is a lightweight antivirus engine built in Python. It uses YARA rules to detect malware, ransomware, RATs, and suspicious files. You can also monitor folders in real-time to catch threats immediately.

Why it’s fun:

Learn how antivirus software works under the hood.

Test files safely in a controlled environment.

Explore real-world malware detection rules.

Hands-on Python, GUI, and real-time monitoring experience.

⚡ Features

✅ YARA-based scanning: Detects threats using .yar or .yara rules.

✅ File & folder scanning: Scan a single file or entire directories.

✅ Real-time monitoring (RTM): Monitor folders for new or modified files.

✅ Interactive GUI: Simple, clean interface using Tkinter.

✅ Extensible rules: Easily add your own YARA rules.

🛠️ Installation

Clone the repository:

git clone https://github.com/yourusername/python-antivirus-demo.git
cd python-antivirus-demo


Create a virtual environment (optional but recommended):

python -m venv venv
source venv/bin/activate    # Linux / macOS
venv\Scripts\activate       # Windows


Install dependencies:

pip install -r requirements.txt


Requirements include: yara-python, watchdog, tkinter (built-in with Python)

Add YARA rules: Place .yar or .yara files inside the rules/ folder. You can download open-source rules from YARA-Rules GitHub
.

🚀 Usage
Run the GUI
python gui.py


Select a file or folder.

Click Scan to check for matches.

Toggle RTM ON/OFF to monitor folders in real-time.

View scan results and RTM logs directly in the GUI.

Run Command-Line Test (Optional)
python test_yara.py


Quickly test YARA rules against a sample file.

Example output:

Matched rules: [test_malware]

🧩 Folder Structure
antiviruscn/
│
├─ gui.py                  # Main Python GUI
├─ rules/                  # Folder for YARA rules
│   ├─ sample_text.yar
│   ├─ sample_pe.yar
│   └─ sample_webshell.yar
├─ testfolder/             # Folder to test RTM
└─ test_yara.py            # Command-line test script

📂 Adding Your Own YARA Rules

Create a .yar file in the rules/ folder.

Define rules like this:

rule TestMalware
{
    meta:
        author = "YourName"
        description = "Detects test malware"
    strings:
        $a = "malicious_string"
    condition:
        $a
}


Run gui.py and your new rule will automatically load.

⚠️ Notes

Some rules may fail to compile if they rely on unsupported features (like is_elf on Windows).

Windows Defender may block downloads from YARA rule repositories. Use trusted sources and run in a safe environment.

🌟 Contributing

Contributions are welcome!

Add new YARA rules.

Improve GUI design or add features.

Report bugs or issues on GitHub.

📄 License

This project is licensed under MIT License.
YARA rules may have their own licenses (check their headers).
