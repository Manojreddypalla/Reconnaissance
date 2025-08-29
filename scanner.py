# scanner.py
import os
import ssl
import socket
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

# Optional libs with graceful failure
try:
    import whois
except ImportError:
    whois = None

try:
    import dns.resolver as dnsresolver
except ImportError:
    dnsresolver = None


class Scanner:
    """A class to encapsulate all OSINT scanning modules."""

    def __init__(self, target_domain: str, progress_callback=None):
        self.target_domain = self._safe_domain_from_input(target_domain)
        self.progress_callback = progress_callback
        self.results = {}

    def _update_progress(self, module_name: str, status: str = "Completed"):
        """Updates the GUI via the provided callback."""
        if self.progress_callback:
            self.progress_callback(f"{module_name}: {status}")

    def _safe_domain_from_input(self, target: str) -> str:
        """Extracts a clean domain from user input (URL or domain)."""
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        parsed_uri = urlparse(target)
        return parsed_uri.netloc

    def run_full_scan(self):
        """Orchestrates the execution of all scanning modules."""
        scans = {
            "WHOIS": self._scan_whois,
            "DNS Records": self._scan_dns,
            "SSL Certificate": self._scan_ssl,
            "HTTP Headers": self._scan_http_headers,
            "Tech Stack": self._scan_tech_stack,
            "HTML Metadata": self._scan_html_meta,
            "Admin Panel Finder": self._scan_admin_panels,
        }

        for name, scan_func in scans.items():
            try:
                self._update_progress(name, "Scanning...")
                self.results[name] = scan_func()
                self._update_progress(name, "Done")
            except Exception as e:
                self.results[name] = {"error": str(e)}
                self._update_progress(name, "Error")
        
        return self.results

    def _scan_whois(self) -> dict:
        if not whois:
            return {"error": "python-whois library not installed."}
        w = whois.whois(self.target_domain)
        # Convert datetime objects to strings for serialization
        for key, value in w.items():
            if isinstance(value, list):
                w[key] = [str(v) for v in value]
            else:
                w[key] = str(value)
        return w

    def _scan_dns(self) -> dict:
        if not dnsresolver:
            return {"error": "dnspython library not installed."}
        data = {}
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
        for rtype in record_types:
            try:
                answers = dnsresolver.resolve(self.target_domain, rtype)
                data[rtype] = [r.to_text() for r in answers]
            except (dnsresolver.NoAnswer, dnsresolver.NXDOMAIN, dnsresolver.Timeout):
                data[rtype] = ["N/A"]
        return data

    def _scan_http_headers(self) -> dict:
        """Try HTTPS first, then fall back to HTTP."""
        urls = [f"https://{self.target_domain}", f"http://{self.target_domain}"]
        for url in urls:
            try:
                r = requests.head(url, timeout=5, allow_redirects=True)
                return {
                    "Final URL": r.url,
                    "Status Code": r.status_code,
                    "Headers": dict(r.headers),
                }
            except requests.RequestException:
                continue
        return {"error": "Could not connect to the server."}

    def _scan_admin_panels(self) -> dict:
        paths_file = os.path.join("assets", "common_admin_paths.txt")
        if not os.path.exists(paths_file):
            return {"error": f"{paths_file} not found."}
            
        with open(paths_file) as f:
            common_paths = [line.strip() for line in f if line.strip()]

        found = []
        for path in common_paths:
            url = f"https://{self.target_domain}/{path}"
            try:
                r = requests.get(url, timeout=3, allow_redirects=False)
                if 200 <= r.status_code < 400:
                    found.append(f"{url} (Status: {r.status_code})")
            except requests.RequestException:
                continue
        return {"Found Panels": found if found else ["None"]}

    def _scan_html_meta(self) -> dict:
        try:
            r = requests.get(f"https://{self.target_domain}", timeout=5)
            soup = BeautifulSoup(r.text, "html.parser")
            meta_info = {
                tag.get("name", tag.get("property", "N/A")): tag.get("content", "N/A")
                for tag in soup.find_all("meta")
                if tag.get("content")
            }
            return meta_info if meta_info else {"info": "No meta tags found."}
        except requests.RequestException as e:
            return {"error": str(e)}

    def _scan_tech_stack(self) -> dict:
        try:
            r = requests.get(f"https://{self.target_domain}", timeout=5)
            headers = r.headers
            soup = BeautifulSoup(r.text, "html.parser")
            result = {}

            # Server and other tech headers
            tech_headers = ["Server", "X-Powered-By", "X-AspNet-Version"]
            for header in tech_headers:
                if header in headers:
                    result[header] = headers[header]

            # Meta generator tag
            generator = soup.find("meta", attrs={"name": "generator"})
            if generator:
                result["Generator"] = generator.get("content", "N/A")
            
            return result if result else {"info": "No specific tech stack info found."}
        except requests.RequestException as e:
            return {"error": str(e)}

    def _scan_ssl(self) -> dict:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.target_domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.target_domain) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        "Subject": dict(x[0] for x in cert.get('subject', [])),
                        "Issuer": dict(x[0] for x in cert.get('issuer', [])),
                        "Valid From": cert.get('notBefore'),
                        "Valid To": cert.get('notAfter'),
                        "Subject Alt Names": [val for typ, val in cert.get('subjectAltName', []) if typ == 'DNS'],
                    }
        except Exception as e:
            return {"error": str(e)}