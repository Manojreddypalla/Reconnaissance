# 🔍 Automated Reconnaissance Tool

A simple yet powerful OSINT (Open-Source Intelligence) tool with a modern, graphical user interface built using Python and Tkinter. This tool allows you to quickly gather essential information about a target domain and export the findings to a PDF report.

![Application Screenshot](screenshot.png)

## ✨ Features

*   **WHOIS Lookup:** Fetches domain registration details.
*   **DNS Record Enumeration:** Gathers common DNS records (A, AAAA, MX, NS, TXT, CNAME).
*   **SSL Certificate Analysis:** Retrieves details about the target's SSL certificate.
*   **HTTP Header Inspection:** Shows response headers from the web server.
*   **Technology Stack Detection:** Attempts to identify the web server and other technologies.
*   **Admin Panel Finder:** Scans for common administrative interface paths.
*   **PDF Report Generation:** Exports all gathered information into a clean PDF document.
*   **Modern UI:** A responsive and good-looking interface built with `ttkthemes`.

## 🛠️ Prerequisites

Before you begin, ensure you have the following installed on your system:

*   **Python 3.6 or newer.** [Download it here.](https://www.python.org/downloads/)
*   **Git** (for cloning the repository). [Download it here.](https://git-scm.com/)
*   **Tkinter** (usually included with Python, but sometimes separate on Linux).
    *   On Debian/Ubuntu/Mint: `sudo apt update && sudo apt install python3-tk`

## 🚀 Installation & Setup

Follow these steps to get the tool running on your machine.

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/your-username/recon-tool.git
    cd recon-tool
    ```
    *(Replace the URL with your own if you have a remote repository.)*

2.  **Create a Virtual Environment**
    ```bash
    python -m venv venv
    ```

3.  **Activate the Virtual Environment**
    *   **On Windows (Command Prompt):**
        ```cmd
        venv\Scripts\activate.bat
        ```
    *   **On Windows (PowerShell):**
        ```ps1
        .\venv\Scripts\Activate.ps1
        ```
    *   **On Linux/macOS:**
        ```bash
        source venv/bin/activate
        ```
    Your command prompt should now show `(venv)`.

4.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

## 🏃‍♀️ How to Run

Once the setup is complete, running the tool is simple:

1.  Ensure your virtual environment is activated (you see `(venv)` in your terminal).
2.  Run the main script:
    ```bash
    python main.py
    ```
3.  The graphical interface will launch. Enter a target domain (e.g., `example.com`) and click "Start Recon"!

## 📦 Dependencies

This project uses the following key Python packages, which are listed in `requirements.txt`:

*   `requests` - For making HTTP requests.
*   `beautifulsoup4` - For web scraping and technology detection.
*   `python-whois` - For performing WHOIS lookups.
*   `dnspython` - For querying DNS records.
*   `reportlab` - For generating PDF reports.
*   `ttkthemes` - For the modern GUI theme.
*   `Pillow` - For image handling in the GUI (if needed).

## 📁 Team

- **Employee ID:** ST#IS#7329  
- **Email:** manojreddypalla947@gmail.com

