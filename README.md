# RIKA V3

A lightweight multithreaded web path fuzzer written in Python for authorized security testing.

## Features

* Multithreaded HTTP requests
* Connection pooling
* Automatic retries
* Custom User-Agent
* Custom HTTP headers
* GET / HEAD requests
* URL path fuzzing
* Extension fuzzing
* Status-code filtering
* Response-size filtering
* Word-count filtering
* Line-count filtering
* Redirect control
* TLS verification control
* Request rate limiting
* Progress display
* Graceful Ctrl+C handling
* TXT / JSON / CSV output
* Python package installation with `pip install .`
* PyInstaller executable support

## Requirements

* Python 3.9+
* requests
* colorama
* chardet

## Installation

### Clone

```bash
git clone https://github.com/YOUR_USERNAME/RIKA.git
cd Rika
```

### Virtual environment

Linux / Kali:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows:

```powershell
py -m venv .venv
.venv\Scripts\activate
```

### Install the project

```bash
python -m pip install .
```

The dependencies are installed automatically from `pyproject.toml`.

### Development installation

If you are actively modifying the source:

```bash
python -m pip install -e .
```

## Verify installation

```bash
rika
```

You can also run:

```bash
python rika
```

## Basic Usage

```bash
rika -u https://example.com/FUZZ -w wordlist.txt
```

Only test systems where you have explicit authorization.

## Threads

```bash
rika
    -u https://example.com/FUZZ \
    -w wordlist.txt \
    -t 20
```

## Extensions

```bash
rika
    -u https://example.com/FUZZ \
    -w wordlist.txt \
    -e php,html,txt,json
```

Example generated paths:

```text
/admin
/admin.php
/admin.html
/admin.txt
/admin.json
```

## Status Code Filtering

Example:

```bash
rika
    -u https://example.com/FUZZ \
    -w wordlist.txt \
    --status 200,204,301,302,403
```

## Response Size Filtering

```bash
rika
    -u https://example.com/FUZZ \
    -w wordlist.txt \
    --size 1234
```

## Word Filtering

```bash
rika
    -u https://example.com/FUZZ \
    -w wordlist.txt \
    --words 50
```

## Line Filtering

```bash
rika
    -u https://example.com/FUZZ \
    -w wordlist.txt \
    --lines 25
```

## HTTP Method

GET:

```bash
rika
    -u https://example.com/FUZZ \
    -w wordlist.txt \
    -m GET
```

HEAD:

```bash
rika
    -u https://example.com/FUZZ \
    -w wordlist.txt \
    -m HEAD
```

## Custom Headers

Example:

```bash
rika
    -u https://example.com/FUZZ \
    -w wordlist.txt \
    -H "X-Test:

rika
```

Multiple headers can be supplied:

```bash
rika
    -u https://example.com/FUZZ \
    -w wordlist.txt \
    -H "X-Test:

rika
    -H "Accept: application/json"
```

## Redirects

Disable redirects:

```bash
rika
    -u https://example.com/FUZZ \
    -w wordlist.txt \
    --no-redirect
```

## TLS Verification

For an authorized lab using a self-signed certificate:

```bash
rika
    -u https://example.local/FUZZ \
    -w wordlist.txt \
    --no-tls-verify
```

Use this only when necessary.

## Rate Limiting

Example:

```bash
rika
    -u https://example.com/FUZZ \
    -w wordlist.txt \
    --delay 0.2
```

This adds a delay between requests to reduce load on the target.

## Output

### TXT

```bash
rika
    -u https://example.com/FUZZ \
    -w wordlist.txt \
    -o results.txt
```

### JSON

```bash
rika
    -u https://example.com/FUZZ \
    -w wordlist.txt \
    --json results.json
```

### CSV

```bash
rika
    -u https://example.com/FUZZ \
    -w wordlist.txt \
    --csv results.csv
```

## Example

```bash
rika
    -u https://example.com/FUZZ \
    -w wordlist.txt \
    -t 30 \
    -e php,html,txt \
    --status 200,204,301,302,403 \
    --delay 0.05 \
    --json results.json
```

## Package Installation

Install locally:

```bash
python -m pip install .
```

Editable/development mode:

```bash
python -m pip install -e .
```

Uninstall:

```bash
python -m pip uninstall rika
```

## Build Python Package

Install build:

```bash
python -m pip install build
```

Build:

```bash
python -m build
```

The generated packages will appear inside:

```text
dist/
```

## Build Standalone Executable

Install PyInstaller:

```bash
python -m pip install pyinstaller
```

Build:

```bash
pyinstaller --onefile --name RIKA
```

The executable will be generated inside:

```text
dist/
```

Linux:

```bash
./dist/RIKA 
```

Windows:

```powershell
.\dist\RIKA 
```

PyInstaller builds for the operating system it is running on, so build the Windows executable on Windows and the Linux executable on Linux.

## Project Structure

```text
RIKA 
│
├── RIKA 
├── pyproject.toml
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore
```

## Development

Run directly:

```bash
python RIKA h
```

Install editable:

```bash
python -m pip install -e .
```

Then:

```bash
RIKA 
```

## Roadmap

### V3.1

* Baseline response detection
* Better wildcard detection
* Improved output formatting
* Configuration file
* More detailed statistics

### V4

* Recursive directory discovery
* Smart wildcard filtering
* Async HTTP engine
* Plugin architecture
* Request templates
* Advanced response comparison
* Better crawling integration

## Disclaimer

RIKA ntended for authorized security testing, CTFs, penetration-testing labs, and systems where you have explicit permission to perform testing.

The author is not responsible for misuse, unauthorized scanning, disruption, or damage caused by this software.

## License

RIKA eleased under the MIT License.

Copyright (c) 2026 hancock.
