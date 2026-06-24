import sqlite3
import json
import time
import datetime
import os
import requests

CACHE_DB_NAME = "cve_cache.db"
NVD_API_URL = os.environ.get("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")

class NVDClient:
    def __init__(self, api_key=None, cache_expiry_days=7):
        self.api_key = api_key
        self.cache_expiry_seconds = cache_expiry_days * 24 * 60 * 60
        self.last_request_time = 0.0
        
        # Determine NVD URL dynamically to support mock testing redirects
        self.api_url = os.environ.get("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
        
        # Determine NVD delay: 50 requests/30s = 0.6s with key; 5 requests/30s = 6.0s without key
        self.request_delay = 0.65 if api_key else 6.5
        
        # State tracking for auto-offline fallback (Phase 3 resilience)
        self.offline_mode = False
        self.consecutive_failures = 0
        
        # Initialize SQLite Cache
        self._init_cache()
        
    def _init_cache(self):
        """Initialize SQLite database for caching NVD responses."""
        self.conn = sqlite3.connect(CACHE_DB_NAME, check_same_thread=False)
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_cache (
                query_key TEXT PRIMARY KEY,
                results_json TEXT,
                timestamp REAL
            )
        """)
        self.conn.commit()

    def _get_cached_results(self, query_key):
        """Retrieve cached results if they exist and are not expired."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT results_json, timestamp FROM cve_cache WHERE query_key = ?", (query_key,))
        row = cursor.fetchone()
        if row:
            results_json, timestamp = row
            # Check if cache expired
            if time.time() - timestamp < self.cache_expiry_seconds:
                try:
                    return json.loads(results_json)
                except json.JSONDecodeError:
                    pass
        return None

    def _save_to_cache(self, query_key, results):
        """Save results to SQLite cache with current timestamp."""
        cursor = self.conn.cursor()
        results_json = json.dumps(results)
        cursor.execute(
            "INSERT OR REPLACE INTO cve_cache (query_key, results_json, timestamp) VALUES (?, ?, ?)",
            (query_key, results_json, time.time())
        )
        self.conn.commit()

    def _wait_for_rate_limit(self):
        """Enforce rate limits between requests."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.request_delay:
            sleep_time = self.request_delay - elapsed
            time.sleep(sleep_time)
        self.last_request_time = time.time()

    def extract_cve_details(self, nvd_vuln_item):
        """
        Parse raw NVD vulnerability item and extract CVE ID, CVSS score, and description.
        """
        cve_data = nvd_vuln_item.get("cve", {})
        cve_id = cve_data.get("id", "Unknown-CVE")
        
        # 1. Parse description (prefer English)
        description = "No description available."
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
                
        # 2. Extract CVSS Score
        cvss_score = 0.0
        metrics = cve_data.get("metrics", {})
        
        # Check CVSS v3.1, v3.0, then v2
        parsed_score = False
        for metric_version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if metric_version in metrics and metrics[metric_version]:
                # Pick Primary source if possible, otherwise first available
                metric_list = metrics[metric_version]
                primary_metric = next((m for m in metric_list if m.get("type") == "Primary"), metric_list[0])
                cvss_data = primary_metric.get("cvssData", {})
                if cvss_data:
                    cvss_score = float(cvss_data.get("baseScore", 0.0))
                    parsed_score = True
                    break
        
        return {
            "id": cve_id,
            "score": cvss_score,
            "description": description
        }

    def lookup_cves(self, service_name, version, console=None, verbose=0):
        """
        Query NVD API for CVEs matching a service and version.
        Handles rate limits, exponential backoff, caching, and result sorting.
        """
        # If no version was found, we cannot perform a keyword-based vulnerability lookup
        if not version:
            return []
            
        # Clean service and version for query
        service_clean = service_name.replace("/", " ").replace("-", " ").strip()
        version_clean = version.strip()
        query_key = f"{service_clean} {version_clean}".lower()
        
        # Check offline mode at the very start of the method
        if self.offline_mode:
            cached = self._get_cached_results(query_key)
            if cached is not None:
                cached.sort(key=lambda x: x["score"], reverse=True)
                if console and verbose >= 1:
                    console.print(f"[dim blue]Cache hit for: '{query_key}' (loaded {len(cached)} CVEs)[/dim blue]")
                return cached
            else:
                if console and verbose >= 1:
                    console.print(f"    [dim yellow]-> NVD API offline fallback. Skipping live query.[/dim yellow]")
                return []
        
        # 1. Check cache first
        cached = self._get_cached_results(query_key)
        if cached is not None:
            # Sort cached results by score descending
            cached.sort(key=lambda x: x["score"], reverse=True)
            if console and verbose >= 1:
                console.print(f"[dim blue]Cache hit for: '{query_key}' (loaded {len(cached)} CVEs)[/dim blue]")
            return cached
            
        # 2. Query NVD API with retries/exponential backoff
        url = self.api_url
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
            
        params = {
            "keywordSearch": f"{service_clean} {version_clean}"
        }
        
        max_retries = 3
        backoff = 1.5
        results = []
        
        if console and verbose >= 1:
            console.print(f"[bold yellow]*[/bold yellow] Querying NVD API for: '{service_clean} {version_clean}'...")
        if console and verbose >= 3:
            console.print(f"[dim grey]  [Debug] Request URL: {url} | Params: {params} | Key present: {bool(self.api_key)}[/dim grey]")
            
        for attempt in range(max_retries):
            self._wait_for_rate_limit()
            try:
                response = requests.get(url, headers=headers, params=params, timeout=6)
                
                # Check for rate limits or server issues
                if response.status_code in (403, 429):
                    self.consecutive_failures += 1
                    if self.consecutive_failures >= 2:
                        self.offline_mode = True
                        if console:
                            console.print(f"[bold yellow]![/bold yellow] [yellow]NVD API appears to be rate-limiting or offline. Switching to offline cache-only mode.[/yellow]")
                        return []
                    if console and verbose >= 1:
                        console.print(f"[bold red]![/bold red] Rate limit hit on NVD API (HTTP {response.status_code}). Retrying in {backoff} seconds... (Attempt {attempt+1}/{max_retries})")
                    time.sleep(backoff)
                    backoff *= 1.5
                    continue
                elif response.status_code != 200:
                    self.consecutive_failures += 1
                    if self.consecutive_failures >= 2:
                        self.offline_mode = True
                        if console:
                            console.print(f"[bold yellow]![/bold yellow] [yellow]NVD API appears to be rate-limiting or offline. Switching to offline cache-only mode.[/yellow]")
                        return []
                    if console and verbose >= 1:
                        console.print(f"[bold red]![/bold red] API returned HTTP error {response.status_code}. Retrying in {backoff} seconds... (Attempt {attempt+1}/{max_retries})")
                    time.sleep(backoff)
                    backoff *= 1.5
                    continue
                
                # Successful response
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                
                for vuln in vulnerabilities:
                    cve_details = self.extract_cve_details(vuln)
                    results.append(cve_details)
                    
                # Sort by CVSS score descending
                results.sort(key=lambda x: x["score"], reverse=True)
                
                # Reset consecutive failures on success
                self.consecutive_failures = 0
                
                # Cache and return results
                self._save_to_cache(query_key, results)
                return results
                
            except requests.RequestException as e:
                self.consecutive_failures += 1
                if self.consecutive_failures >= 2:
                    self.offline_mode = True
                    if console:
                        console.print(f"[bold yellow]![/bold yellow] [yellow]NVD API appears to be rate-limiting or offline. Switching to offline cache-only mode.[/yellow]")
                    return []
                if console and verbose >= 1:
                    console.print(f"[bold red]![/bold red] Connection error: {str(e)}. Retrying in {backoff} seconds... (Attempt {attempt+1}/{max_retries})")
                time.sleep(backoff)
                backoff *= 1.5
                
        # If all retries failed without triggering offline mode (unlikely, but as safety fallback)
        self.consecutive_failures += 1
        if self.consecutive_failures >= 2:
            self.offline_mode = True
            if console:
                console.print(f"[bold yellow]![/bold yellow] [yellow]NVD API appears to be rate-limiting or offline. Switching to offline cache-only mode.[/yellow]")
        if console and verbose >= 1:
            console.print(f"[bold red]Failed to get CVE details from NVD API after {max_retries} attempts.[/bold red]")
        return []
        
    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass
