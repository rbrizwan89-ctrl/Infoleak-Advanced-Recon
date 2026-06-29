# Infoleak v1.0 - Advanced Information Disclosure & Recon Script

`infoleak` is a powerful Bash automation script designed for Bug Bounty hunters and Penetration Testers. It automates the process of passive reconnaissance, endpoint extraction, asset classification, and active vulnerability/secret scanning on a target domain.

The tool focuses heavily on identifying **Information Disclosures**, hardcoded tokens, exposed infrastructure configuration files, and potential targets for logical flaws like **IDOR** and **Access Control bypasses**.

---

## 🚀 Features

* **Smart Subdomain Fallback:** Automatically fallbacks and tests the apex domain if passive subdomain enumeration returns empty.
* **Aggressive Endpoint Gathering:** Combines historic and dynamic URLs using `gau` and `katana`.
* **Noise Reduction:** Filters out static media assets (`.jpg`, `.png`, `.css`, etc.) to keep parsing loads optimal.
* **Target Isolation for Logical Flaws:**
  * Extracts API & REST endpoints.
  * Isolates cloud buckets and third-party leaks (AWS S3, Firebase, Azure, GitHub).
  * Pinpoints potential **IDOR** parameters (e.g., `?uid=`, `?invoice_id=`).
  * Extracts Authentication & Session management paths.
* **Active Validation:** Uses `httpx` to check live exposure status (HTTP 200) for high-risk sensitive files (`.env`, `.git`, `.bak`).
* **Automated Secret Scanning:** Integrates `nuclei` to scan extracted JavaScript files for hardcoded secrets/tokens and exposed infrastructure panels.

---

## 🛠️ Prerequisites

Ensure you have the following tools installed and available in your `$PATH`:
* [Subfinder](https://github.com/projectdiscovery/subfinder)
* [Httpx](https://github.com/projectdiscovery/httpx)
* [GAU (GetAllUrls)](https://github.com/lc/gau)
* [Katana](https://github.com/projectdiscovery/katana)
* [Nuclei](https://github.com/projectdiscovery/nuclei)

---

## 💻 Installation & Usage

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/rbrizwan89-ctrl/Infoleak-Advanced-Recon.git](https://github.com/rbrizwan89-ctrl/Infoleak-Advanced-Recon.git)
   cd Infoleak-Advanced-Recon
