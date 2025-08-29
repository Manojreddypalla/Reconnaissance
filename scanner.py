# scanner.py
import os
import ssl
import socket
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

# --- UPDATED --- : Added builtwith
try:
    import whois
    import dns.resolver as dnsresolver
    import builtwith
except ImportError:
    whois = None
    dnsresolver = None
    builtwith = None


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

    # --- UPDATED --- : run_full_scan now handles IP dependency for geolocation
    def run_full_scan(self):
        """Orchestrates the execution of all scanning modules."""
        
        # Resolve IP once at the start
        ip_address = self._resolve_ip()
        self.results["IP Address"] = ip_address if ip_address else "Not Found"

        scans = {
            "WHOIS": self._scan_whois,
            "DNS Records": self._scan_dns,
            "IP Geolocation": lambda: self._scan_geolocation(ip_address), # Pass IP to function
            "SSL Certificate": self._scan_ssl,
            "HTTP Headers": self._scan_http_headers,
            "Robots.txt & Sitemap.xml": self._scan_robots_sitemap, # New scan
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

    def _resolve_ip(self) -> str | None:
        """Resolves the domain to an IP address."""
        try:
            return socket.gethostbyname(self.target_domain)
        except socket.gaierror:
            return None

    # --- NEW --- : Added IP Geolocation function
    def _scan_geolocation(self, ip_address: str | None) -> dict:
        """Gets physical location data from an IP address."""
        if not ip_address:
            return {"error": "Cannot geolocate without an IP address."}
        try:
            response = requests.get(f"https://ipinfo.io/{ip_address}/json", timeout=5)
            response.raise_for_status()
            data = response.json()
            return {
                "City": data.get("city", "N/A"),
                "Region": data.get("region", "N/A"),
                "Country": data.get("country", "N/A"),
                "Location": data.get("loc", "N/A"),
                "Organization": data.get("org", "N/A"),
            }
        except requests.RequestException as e:
            return {"error": f"API request failed: {e}"}

    # --- NEW --- : Added robots.txt and sitemap.xml checker
    def _scan_robots_sitemap(self) -> dict:
        """Checks for the existence and content of robots.txt and sitemap.xml."""
        results = {}
        for file in ["robots.txt", "sitemap.xml"]:
            try:
                url = f"https://{self.target_domain}/{file}"
                r = requests.get(url, timeout=5)
                if r.status_code == 200:
                    results[file] = r.text.strip()
                else:
                    results[file] = "Not found (Status: {r.status_code})"
            except requests.RequestException:
                results[file] = "Failed to retrieve."
        return results

    # --- UPDATED --- : Tech stack scan now uses the powerful 'builtwith' library
    def _scan_tech_stack(self) -> dict:
        """Identifies technologies used on the website using the builtwith library."""
        if not builtwith:
            return {"error": "builtwith library not installed."}
        try:
            # Prepend https:// as builtwith expects a full URL
            url = f"https://{self.target_domain}"
            tech_info = builtwith.parse(url)
            return tech_info if tech_info else {"info": "No specific technologies identified."}
        except Exception as e:
            return {"error": str(e)}
    
    # --- The rest of the functions are the same as before ---
    
    def _scan_whois(self) -> dict:
        if not whois:
            return {"error": "python-whois library not installed."}
        w = whois.whois(self.target_domain)
        clean_whois = {}
        for key, value in w.items():
            if isinstance(value, list):
                clean_whois[key] = [str(v) for v in value]
            else:
                clean_whois[key] = str(value)
        return clean_whois

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