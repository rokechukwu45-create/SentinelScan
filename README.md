
# SentinelScan

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)

**SentinelScan** is a zero-dependency, highly concurrent command-line interface (CLI) tool and library written in pure Python. It is designed for ethical hackers, penetration testers, and security engineers to discover, audit, and flag exposed cloud metadata fabrics, link-local configuration leaks, and service tokens from AWS, GCP, Azure, DigitalOcean, and Kubernetes environments.

Features a multi-layered detection engine combining bounded, ReDoS-safe regular expressions with an advanced noise-reduction filter (Shannon entropy analysis, test-placeholder filtering, and structural JWT validation) to keep false positives to an absolute minimum.

---

## Installation

You can install `sentinelscan` either directly from the GitHub repository or locally using `pip`.

### 1. Install via GitHub (Recommended for development)
To pull the codebase directly from GitHub and install it in editable mode:
```bash
git clone [https://github.com/rokechukwu45-create/SentinelScan.git](https://github.com/rokechukwu45-create/SentinelScan.git)
cd SentinelScan
pip install -e .

```
### 2. Install via Pip (Local or Git Link)
If you want to install it straight into your Python environment without manually downloading the repository, run:
```bash
pip install git+[https://github.com/rokechukwu45-create/SentinelScan.git](https://github.com/rokechukwu45-create/SentinelScan.git)

```
## CLI Usage & Arguments
Once installed, you can invoke the tool directly using either the sentinelscan executable or via Python's module runner:
```bash
sentinelscan [OPTIONS]
# OR
python -m sentinelscan [OPTIONS]

```
### Available Arguments
| Argument | Long Flag | Value | Description |
|---|---|---|---|
| -t | --target | BASE_URL | External base URL for SSRF/proxy-based scanning. When omitted, the tool automatically probes the default local link-local (169.254.169.254) environment. |
| -o | --output | text | json | Choice of output formatting. text provides a clean, structured, and colorized terminal layout. json outputs parseable machine-readable data. (Default: text) |
|  | --timeout | FLOAT | Network connection and read timeout limit per endpoint in seconds. (Default: 4.0) |
|  | --workers | INT | Total number of concurrent worker threads allocated to the execution pool. (Default: 20) |
|  | --no-imdsv2 | *None* | Skips the automated, tight-timeout AWS IMDSv2 token acquisition (PUT request) probe. |
|  | --no-color | *None* | Forces disabling of ANSI color escape sequences in text mode. Colors are also automatically dropped if standard output is piped to a file. |
|  | --no-noise-filter | *None* | Disables false-positive logic (entropy baselines, placeholder matching). Useful for debugging patterns or capturing raw strings. |
### Example CLI Commands
**Scan the local machine / container context with customized timeout rules:**
```bash
sentinelscan --workers 30 --timeout 2.5

```
**Perform an SSRF/Proxy assessment against a remote web asset, printing output to a JSON file:**
```bash
sentinelscan --target "[http://example.com/proxy?url=](http://example.com/proxy?url=)" --output json > results.json

```
## Importing into Your Code
You can easily trigger sentinelscan programmatically within your own automation scripts, automated pipelines, or scheduled tools by importing its execution engine and feeding it custom CLI arguments:
```python
import sys
from sentinelscan import main

def run_automated_audit():
    print("[*] Initiating SentinelScan cloud metadata security check...")
    
    # Pass arguments exactly as you would on the command line
    arguments = ["--workers", "15", "--timeout", "3.0"]
    
    # Example: scanning a specific remote proxy or SSRF vector instead
    # arguments = ["--target", "[http://example.com/proxy?url=](http://example.com/proxy?url=)", "--output", "json"]
    
    try:
        # main handles argument arrays cleanly and returns the standard Unix exit status
        exit_code = main(arguments)
        if exit_code == 0:
            print("[+] Scan completed. No exposed infrastructure fabrics flagged.")
        else:
            print(f"[!] Scan finished with findings or issues. Exit code: {exit_code}")
    except Exception as e:
        print(f"[-] Execution framework failed: {e}")

if __name__ == "__main__":
    run_automated_audit()

```
## License
This project is licensed under the Apache License 2.0. It is intended strictly for authorized security testing, compliance auditing, and educational evaluation. Pre-verified authorization is required by platform Terms of Service before scanning external cloud interfaces.
```

***

### Step-by-Step commands to put this on GitHub:

1. Open `README.md` inside your directory:
   ```bash
   nano README.md

```
 2. Copy the code block above and paste it inside the file.
 3. Save and close Nano (Ctrl + O, Enter, then Ctrl + X).
 4. Commit the change and push it up to your repository:
   ```bash
   git add README.md
   git commit -m "Update README with correct package name and import method"
   git push
   
   ```

    # 3. Initialize the orchestrator engine
    scanner = CloudIDHunter(
        targets=targets,
        timeout=3.0,
        max_workers=15,
        enable_imdsv2=True
    )

    print("[*] Initiating concurrent cloud metadata exposure sweep...")
    scanner.run()

    # 4. Process finding results programmatically
    if scanner.has_exposure():
        print(f"[!] Warning: {len(scanner.findings)} potential credential leak(s) or open metadata roots detected!")
        for finding in scanner.findings:
            print(f"\n[-] [{finding.severity}] Provider: {finding.provider}")
            print(f"    Endpoint: {finding.endpoint}")
            print(f"    Description: {finding.description}")
            print(f"    Remediation: {finding.remediation}")
    else:
        print("[+] Environment appears safe. No exposed metadata fabrics verified.")

if __name__ == "__main__":
    run_custom_security_scan()

```
## License
This project is licensed under the Apache License 2.0. It is intended strictly for authorized security testing, compliance auditing, and educational evaluation. Pre-verified authorization is required by platform Terms of Service before scanning external cloud interfaces.
