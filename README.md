# Python Code Analyzer
Analyze suspicious Python scripts: detection score, safe preview, CLI and local web interface

A tool to analyze, deobfuscate, and inspect potentially malicious Python scripts.

## Features
- **Web UI**: Drag & drop file analysis with instant visual results.
- **Obfuscation Detection**: Detects common packing and obfuscation techniques.
- **Safe Preview**: Shows a safe, de-armed version of the code.
- **Database History**: Keeps track of all your scans in a local database.
- **Batch Processing**: Scan entire folders at once.

## Windows Installation Guide

### 1. Prerequisites
- **Python 3.10 or higher**: Download from [python.org](https://www.python.org/downloads/).
  > **Important**: Check the box **"Add Python to PATH"** during installation.

### 2. Setup
Open your terminal (Command Prompt or PowerShell) and navigate to the project folder:

```cmd
cd Path\to\PyCode_Analyzer
```

Install the required libraries:

```cmd
python -m pip install -r requirements.txt
```

---

## How to Use

### Option 1: Web Interface (Recommended)
This launches a local web server where you can upload files and view reports.

1. Start the server:
   ```cmd
   python -m uvicorn api.main:app --reload --port 8000
   ```
   *(If `python` doesn't work, try `py` instead)*

2. Open your browser and go to:
   **[http://127.0.0.1:8000](http://127.0.0.1:8000)**

3. Upload a file or paste code to analyze it!

### Option 2: Command Line (CLI)
Use this for quick checks or batch processing.

**Analyze a single file:**
```cmd
python main.py samples/sample_50.py --save
```

**Scan an entire folder:**
```cmd
python main.py --batch my_folder/ --save
```

**View Results:**
Results are saved to `analysis.db`. You can view them in the Web UI under "Recent Scans".
