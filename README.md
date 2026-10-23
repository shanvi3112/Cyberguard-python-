# CyberGuard — Python Cybersecurity Toolkit

CyberGuard is a beginner-friendly, defensive cybersecurity dashboard built with Python and Streamlit.

## Features

- **Password Analyzer:** Local heuristic checks for length, character variety, common passwords, and repeated characters. Passwords are not saved.
- **File Integrity Monitor:** Uses SHA-256 hashes to create a local baseline and detect changes.
- **Security Log Analyzer:** Parses authentication logs and flags IP addresses with repeated failed-login events.
- **Authorized TCP Port Check:** Checks a user-selected list of up to 20 TCP ports on a device you own or are authorized to test.

## Requirements

- Python 3.10+
- pip

## Setup

### Windows (PowerShell)

```powershell
py -m venv .venv
.venv\\Scripts\\Activate.ps1
python -m pip install -r requirements.txt
streamlit run app.py
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
streamlit run app.py
```

Streamlit opens the dashboard in your browser, usually at `http://localhost:8501`.

## Quick demo

1. Open **Password Analyzer** and use a made-up test password.
2. Open **File Integrity**, upload a harmless sample file, and save its baseline. Edit the file and upload it again to compare.
3. Open **Security Log Analyzer** and paste the sample lines from `sample_data/auth.log`.
4. Open **Authorized Port Check** and check a few ports on `127.0.0.1`.

## Project structure

```text
CyberGuard/
├── app.py
├── requirements.txt
├── README.md
├── utils/
│   ├── __init__.py
│   ├── passwords.py
│   ├── integrity.py
│   └── logs.py
├── sample_data/
│   └── auth.log
└── data/
    └── .gitkeep
```

## Safety and limitations

- Only inspect systems, logs, and files you own or have explicit permission to assess.
- The port checker is a simple TCP connection check, not a vulnerability scanner.
- Log patterns are heuristic and can produce false positives or miss events in unfamiliar log formats.
- The password score is educational, not a true entropy estimate or a guarantee of security.
- The baseline JSON file is stored locally. If an attacker can alter both a file and its baseline, this tool alone cannot prove integrity.
- This project does not block attacks, remove malware, or replace professional security tools.

## Suggested extensions

- Add unit tests with `pytest`.
- Add CSV export for log-analysis results.
- Add a file/folder watcher.
- Add login authentication to the dashboard before hosting it.
- Add a report export with timestamps and scan scope.
- Add a configurable log parser for Windows Event logs.

## License

MIT — you may adapt this project for learning and portfolio use.
