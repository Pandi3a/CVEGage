# 🛡️ CVEGage: Stack-Aware Vulnerability Intelligence

**CVEGage** is a targeted security monitoring tool designed to eliminate "Alert Fatigue." By cross-references global vulnerability feeds with the **CISA Known Exploited Vulnerabilities (KEV) catalog**, it identifies which threats in your specific tech stack require immediate, emergency patching.



## 🚀 Core Features

* **Custom Stack Filtering**: Monitors only the tools you actually use (e.g., Kubernetes, Docker, AWS).
* **Intelligent Prioritization**: Flags vulnerabilities that are confirmed to be actively exploited in the wild.
* **Local Caching**: Optimized to minimize API calls and respect rate limits by caching the CISA catalog locally.
* **Executive Briefing**: Generates a "Must-Fix" summary at the end of every scan with official remediation due dates.

---

## 🛠️ Quick Start Guide

### 1. Prerequisites
Ensure you have the following installed:
* **Python 3.9** or higher
* **Requests library**

```
pip install requests
```

### 2. Configuration

Open cvegage.py and update the self.stack list with your infrastructure components:
Python

```
self.stack = ["kubernetes", "docker", "terraform", "aws", "gcp", "mongodb"]
```

### 3. Execution

Run the watcher to pull the latest 5-day delta:
Bash

```
python cvegage.py
```

## 📊 Sample Output

CVEGage provides high-visibility CLI output, making it easy to spot critical threats at a glance.
Plaintext

```
🚀 CVEGage starting full stack scan for: kubernetes, docker, terraform...

🚨 [CISA EXPLOITED] CVE-2024-XXXX (KUBERNETES) | Score: 8.8
   🔥 CISA ALERT: ACTIVELY EXPLOITED
   Tech Impact: KUBERNETES
   Summary: A flaw in the kube-apiserver allows for remote code execution...
   🔗 Detail: https://nvd.nist.gov/vuln/detail/CVE-2024-XXXX

--------------------------------------------------------------------------------
🔥 CVEGage FINAL SUMMARY: CISA MUST-FIX LIST
--------------------------------------------------------------------------------
ID: CVE-2024-XXXX | Affected Stack: KUBERNETES
Action Required: Apply updates per vendor instructions immediately.
Remediation Due: 2026-02-15
--------------------------------------------------------------------------------
```

## 🏗️ How it Works

  *  Ingest: Fetches the latest vulnerabilities from the NIST NVD API.

  *  Verify: Compares CVE IDs against the CISA KEV database.

  *  Cache: Stores a local copy of the CISA catalog (cisa_cache.json) for 24 hours to ensure speed.

  *  Report: Categorizes hits by severity and provides a "Must-Fix" list based on active exploitation status.

## 🛡️ Why use this?

#### In a typical week, hundreds of CVEs are published. For an SRE team, checking every single one is impossible. CVEGage applies the 80/20 rule: 80% of your risk comes from the 20% of bugs that are actually being exploited. This tool ensures those high-risk bugs are never missed.
