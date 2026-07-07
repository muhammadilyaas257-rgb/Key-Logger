# Phishing Analysis Unit

A Python desktop application that analyzes suspected URLs and emails for common phishing indicators. The project was originally built as a single HTML page and has been converted into a modular Python app with a split GUI for input and results.

## Features
- Analyze a suspicious URL
- Analyze a suspicious email
- Load phishing and safe sample inputs
- View a risk score, verdict, and evidence findings
- Separate intake and results panels in the interface

## Project Structure
- `analyzer.py` – contains the phishing heuristic engine and sample data
- `ui.py` – contains the Tkinter-based desktop interface
- `main.py` – launches the application

## Requirements
- Python 3.10+
- Tkinter (usually included with Python on Windows/macOS)

## Run the application
From the project folder, run:

```bash
python main.py
```

If you are using the virtual environment created in this workspace, you can run:

```bash
c:/Users/Kh0khar/Downloads/Check/.venv/Scripts/python.exe c:/Users/Kh0khar/Downloads/Check/main.py
```

## Notes
This tool is intended for educational and demonstration purposes. It uses rule-based heuristics and should not be treated as a replacement for professional security analysis.
