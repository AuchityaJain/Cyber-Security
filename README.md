# SiteGuard Scout: Simple HTTP Header Security Analyzer

## 🚀 Project Overview

**SiteGuard Scout** is a straightforward Python script designed to help anyone quickly assess the fundamental security headers of a website. Think of it as a "security bodyguard checker" for your website. Even without a deep cybersecurity background, you can use this tool to understand if a website has basic protections in place against common web vulnerabilities.

It fetches HTTP headers from any given URL and provides an easy-to-understand report on key security headers like `X-Frame-Options`, `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), `X-Content-Type-Options`, and `Referrer-Policy`. For each header, it explains its purpose, the potential risks if missing, and offers a clear "Good", "Needs Attention", or "Critical" status.

## ✨ Features

* **User-Friendly Output:** Explanations tailored for individuals new to cybersecurity, using simple language and analogies.
* **Key Header Analysis:** Checks for the presence and basic configuration of 5 crucial HTTP security headers.
* **Clear Status Indicators:** Uses "Good ✅", "Needs Attention 🟠", and "Critical 🔴" to highlight security posture.
* **Risk Explanation:** Describes the specific attack (e.g., Clickjacking, XSS) that each header helps prevent.
* **Actionable Advice:** Provides simple recommendations for improving security where issues are found.
* **Python-Based:** Easy to run from your command line.

## 💡 Why This Project?

HTTP Security Headers are often the first line of defense for web applications. Misconfigurations or missing headers can expose websites to significant risks. This project aims to demystify these important security controls, making them accessible to developers, website owners, and anyone interested in understanding basic web security without needing extensive technical knowledge.

## 🛠️ Technologies Used

* **Python 3:** The core programming language.
* **`requests` library:** For making HTTP requests to fetch website headers.
* **`sys` module:** For system-specific parameters and functions (e.g., exiting the script cleanly).

## ⚡ Getting Started

Follow these steps to get `SiteGuard Scout` up and running on your local machine.

### Prerequisites

* **Python 3.x:** Make sure you have Python installed. You can download it from [python.org](https://www.python.org/downloads/).
* **`pip`:** Python's package installer, usually comes with Python.

### Installation

1.  **Clone the repository (or download the script):**
    ```bash
    git clone [https://github.com/YOUR_USERNAME/SiteGuard-Scout.git](https://github.com/YOUR_USERNAME/SiteGuard-Scout.git)
    cd SiteGuard-Scout
    ```
    *(Replace `YOUR_USERNAME` with your GitHub username)*

2.  **Install required Python libraries:**
    ```bash
    pip install requests
    ```

### How to Run

1.  **Open your terminal or command prompt.**

2.  **Navigate to the project directory** where you saved `header_analyzer_simple.py`.

    ```bash
    cd path/to/SiteGuard-Scout
    ```
    *(Replace `path/to/SiteGuard-Scout` with the actual path)*

3.  **Execute the script:**
    ```bash
    python header_analyzer_simple.py
    ```

4.  **Enter the website URL** when prompted (e.g., `https://www.google.com`, `https://www.kaggle.com`).

    ```
    --- Simple Website Security Header Analyzer ---
    This tool checks key 'security bodyguard' settings for any website.
    Just enter the website address (URL) and I'll tell you how well protected it is!

    Enter the full website address (e.g., [https://www.google.com](https://www.google.com)): [https://www.example.com](https://www.example.com)
    ```

## 📈 Example Output (using your Kaggle example)
