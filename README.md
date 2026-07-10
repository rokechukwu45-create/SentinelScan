# SentinelScan

```markdown
# CloudID-Hunter (SentinelScan)

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)

**CloudID-Hunter** (packaged as `sentinelscan`) is a zero-dependency, highly concurrent command-line interface (CLI) tool and library written in pure Python. It is designed for ethical hackers, penetration testers, and security engineers to discover, audit, and flag exposed cloud metadata fabrics, link-local configuration leaks, and service tokens from AWS, GCP, Azure, DigitalOcean, and Kubernetes environments.

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
Once installed, you can invoke the tool directly using either the cloudid-hunter executable or via Python's module runner:
```bash
cloudid-hunter [OPTIONS]
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
cloudid-hunter --workers 30 --timeout 2.5

```
**Perform an SSRF/Proxy assessment against a remote web asset, printing output to a JSON file:**
```bash
cloudid-hunter --target "[http://example.com/proxy?url=](http://example.com/proxy?url=)" --output json > results.json

```
## Importing into Your Code
You can integrate sentinelscan directly into your custom Python tooling, automated scanning pipelines, or orchestration layers.
```python
from sentinelscan.scanner import MetadataTarget, CloudIDHunter, _build_local_targets

def run_custom_security_scan():
    # 1. Gather target instances (using default local link-local configurations)
    targets = _build_local_targets()
    
    # 2. Alternatively, construct individual specific targets dynamically
    # custom_target = MetadataTarget(
    #     provider="AWS Custom", 
    #     url="[http://169.254.169.254/latest/meta-data/](http://169.254.169.254/latest/meta-data/)", 
    #     headers=None, 
    #     description="Custom AWS Assessment Root"
    # )
    # targets.append(custom_target)

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
```

***

### How to apply this to your project repository:
1. In Termux, make sure you are in your project directory: `cd /storage/emulated/0/spider/SentinelScan`
2. Create or overwrite the file: `nano README.md`
3. Paste the contents above, save (`Ctrl + O`, `Enter`), and exit (`Ctrl + X`).
4. Update GitHub using your regular three commands:
   ```bash
   git add README.md
   git commit -m "Added comprehensive documentation README"
   git push

```
