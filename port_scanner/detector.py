import socket
import re
import urllib.parse
from port_scanner.constants import PORT_SERVICE_MAP

def parse_service_banner(banner_str):
    """
    Parse a raw banner string into a cleaned (service_name, version) tuple.
    Accuracy is critical here, as this is used for NVD CVE keywords.
    """
    banner = banner_str.strip()
    if not banner:
        return None, None

    # Replace newlines, tabs, and multiple spaces with a single space
    banner_clean = re.sub(r'\s+', ' ', banner)

    # 1. SSH Banners (e.g., SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5)
    ssh_match = re.search(r'SSH-\d+\.\d+-([A-Za-z0-9_.-]+)_([A-Za-z0-9.+~-]+)', banner_clean)
    if ssh_match:
        service = ssh_match.group(1).strip()
        version = ssh_match.group(2).strip()
        # Clean up service name if it's openSSH, ssh, etc.
        if service.lower() == 'openssh':
            service = 'OpenSSH'
        return service, version

    # Generic SSH format check
    if banner_clean.startswith("SSH-"):
        parts = banner_clean.split("-")
        if len(parts) >= 3:
            # check if last part has name and version separated by underscore
            subparts = parts[2].split("_")
            if len(subparts) == 2:
                return subparts[0].strip(), subparts[1].strip()
            return parts[2].strip(), None

    # 2. FTP Banners
    # Example: "220 (vsFTPd 3.0.3)"
    # Example: "220 ProFTPD 1.3.5 Server"
    # Example: "220-FileZilla Server 0.9.60 beta"
    ftp_match = re.search(
        r'220[\s-](?:\((.*?)\)|([A-Za-z0-9_-]+)\s+([0-9\.]+(?:\s*[a-zA-Z]+[a-zA-Z0-9_-]*)?))',
        banner_clean
    )
    if ftp_match:
        if ftp_match.group(1):  # vsFTPd 3.0.3 style
            inner = ftp_match.group(1).strip()
            parts = inner.split()
            if len(parts) >= 2:
                return parts[0], parts[1]
            return inner, None
        return ftp_match.group(2).strip(), ftp_match.group(3).strip()

    # 3. SMTP Banners
    # Example: "220 mail.example.com ESMTP Postfix"
    # Example: "220 mail.example.com ESMTP Postfix (Ubuntu)"
    smtp_match = re.search(r'220\s+\S+\s+ESMTP\s+([A-Za-z0-9_-]+)(?:\s+([0-9\.]+[-a-zA-Z0-9.]*))?', banner_clean, re.IGNORECASE)
    if smtp_match:
        return smtp_match.group(1).strip(), smtp_match.group(2).strip() if smtp_match.group(2) else None

    # 4. HTTP Server Headers
    # Server headers are already pre-extracted from the GET response, but we might pass
    # the raw Server header here. Example: "Apache/2.4.41 (Unix) OpenSSL/1.1.1d" or "nginx/1.18.0"
    # Match service/version
    http_match = re.search(r'^([A-Za-z0-9_.-]+)/([0-9\.]+(?:\-[a-zA-Z0-9.]+)?)(?:\s|$)', banner_clean)
    if http_match:
        return http_match.group(1).strip(), http_match.group(2).strip()

    # 5. Generic Software version matching
    # Matches strings like "Apache 2.4.41" or "Microsoft-IIS/10.0"
    generic_match = re.search(r'([A-Za-z0-9_-]{2,})\s*[/v\s]\s*(\d+\.\d+(?:\.\d+)?(?:[-a-zA-Z0-9._]+)?)', banner_clean)
    if generic_match:
        return generic_match.group(1).strip(), generic_match.group(2).strip()

    # If we find a version-like string in the banner but couldn't parse it nicely
    version_match = re.search(r'(\d+\.\d+(?:\.\d+)?(?:[-a-zA-Z0-9._]+)?)', banner_clean)
    if version_match:
        # Extract everything before the version as the service name, cleaned up
        idx = banner_clean.find(version_match.group(1))
        service_candidate = banner_clean[:idx].strip().rstrip('/-v ')
        # Filter noise from service candidate (like status codes 220, SMTP domains)
        service_candidate = re.sub(r'^\d{3}\s+', '', service_candidate)  # remove status codes
        service_candidate = service_candidate.split()[-1] if service_candidate.split() else service_candidate
        if len(service_candidate) >= 2:
            return service_candidate, version_match.group(1)

    return banner_clean[:30], None

def grab_standard_banner(ip, port, timeout):
    """
    Attempt to connect and grab a banner by reading immediately.
    Works for SSH, FTP, SMTP, Telnet.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        # Wait for greeting banner
        banner = s.recv(1024).decode('utf-8', errors='ignore')
        return banner.strip()
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass

def grab_http_banner(ip, port, timeout, ssl=False):
    """
    Send a basic HTTP GET request and parse the Server header.
    """
    import urllib.request
    import ssl as ssl_mod
    
    protocol = "https" if ssl else "http"
    url = f"{protocol}://{ip}:{port}/"
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) RiskScanner/1.0'
    }
    req = urllib.request.Request(url, headers=headers)
    
    # Avoid SSL validation errors for scanner
    ctx = ssl_mod.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl_mod.CERT_NONE
    
    try:
        # Timeout is handled globally
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            server_header = response.headers.get('Server')
            if server_header:
                return f"HTTP/{port} {server_header}"
    except urllib.error.HTTPError as e:
        # Even on HTTP error (e.g. 401, 403, 404), the Server header might be present
        server_header = e.headers.get('Server')
        if server_header:
            return f"HTTP/{port} {server_header}"
    except Exception:
        pass
    return None

def detect_service(ip, port, timeout):
    """
    Coordinates service detection for a single open port.
    Returns a dict with keys: 'service', 'version', 'banner', 'confirmed'.
    """
    banner = None
    confirmed = False
    
    # Define ports that are typically HTTP or HTTPS
    http_ports = [80, 8080, 8000, 8081, 8088, 3000, 5000]
    https_ports = [443, 8443, 2083, 2087, 2096, 5986]
    
    # 1. HTTP/HTTPS probe
    if port in http_ports:
        banner = grab_http_banner(ip, port, timeout, ssl=False)
    elif port in https_ports:
        banner = grab_http_banner(ip, port, timeout, ssl=True)
        
    # 2. Try standard banner grabbing if HTTP didn't match or wasn't tried
    if not banner:
        banner = grab_standard_banner(ip, port, timeout)
        
    # 3. Fallback: Try HTTP probe if it wasn't tried (in case HTTP is on non-standard port)
    if not banner and port not in http_ports + https_ports:
        # Try HTTP first, then HTTPS
        banner = grab_http_banner(ip, port, timeout, ssl=False)
        if not banner:
            banner = grab_http_banner(ip, port, timeout, ssl=True)
            
    # 4. Parse the grabbed banner
    if banner:
        # Strip null bytes and replace with space to prevent binary string issues
        banner_clean_nulls = banner.replace('\x00', ' ').strip()
        service, version = parse_service_banner(banner_clean_nulls)
        
        # Check if it's an HTTP or HTTPS service
        is_http_str = (service and service.lower() in ("http", "http-alt", "http-proxy")) or banner_clean_nulls.startswith("HTTP/")
        is_https_str = (service and service.lower() in ("https", "ssl/http"))
        
        http_profile = None
        if is_http_str or port in http_ports:
            from port_scanner.fingerprinter import fingerprint_http
            http_profile = fingerprint_http(ip, port, timeout, is_ssl=False)
            service = "HTTP"
        elif is_https_str or port in https_ports:
            from port_scanner.fingerprinter import fingerprint_http
            http_profile = fingerprint_http(ip, port, timeout, is_ssl=True)
            service = "HTTPS"
            
        if http_profile:
            confirmed = True
            if http_profile.get("server"):
                srv_name_part, srv_ver_part = parse_service_banner(http_profile["server"])
                if srv_name_part:
                    service = srv_name_part
                    version = srv_ver_part
        
        # Service name & version overrides for common ports
        if port == 3306:
            # Extract version from MySQL handshake
            mysql_ver_match = re.search(r'(\d+\.\d+\.\d+(?:[-a-zA-Z0-9.]+)?)', banner_clean_nulls)
            service = "MySQL"
            version = mysql_ver_match.group(1) if mysql_ver_match else None
            confirmed = True
        elif service:
            service_lower = service.lower()
            if port == 22 and ('openssh' in service_lower or service_lower == 'ssh' or len(service) <= 2):
                service = "OpenSSH"
            elif port == 6379:
                service = "Redis"
            elif port == 5432:
                service = "PostgreSQL"
            if not http_profile:
                confirmed = True
        else:
            confirmed = False
            
        if confirmed:
            res_dict = {
                'port': port,
                'service': service,
                'version': version,
                'banner': banner_clean_nulls[:100],  # clean banner output
                'confirmed': confirmed
            }
            if http_profile:
                res_dict['http_profile'] = http_profile
            return res_dict
            
    # 5. Fallback to static mapping if no banner grabbed
    service = PORT_SERVICE_MAP.get(port, "Unknown")
    
    # Try web fingerprinting as a last resort if it's a known web port
    if port in http_ports:
        from port_scanner.fingerprinter import fingerprint_http
        http_profile = fingerprint_http(ip, port, timeout, is_ssl=False)
        if http_profile:
            service = "HTTP"
            version = None
            if http_profile.get("server"):
                srv_name_part, srv_ver_part = parse_service_banner(http_profile["server"])
                if srv_name_part:
                    service = srv_name_part
                    version = srv_ver_part
            return {
                'port': port,
                'service': service,
                'version': version,
                'banner': http_profile.get("server") or "HTTP Web Server",
                'confirmed': True,
                'http_profile': http_profile
            }
    elif port in https_ports:
        from port_scanner.fingerprinter import fingerprint_http
        http_profile = fingerprint_http(ip, port, timeout, is_ssl=True)
        if http_profile:
            service = "HTTPS"
            version = None
            if http_profile.get("server"):
                srv_name_part, srv_ver_part = parse_service_banner(http_profile["server"])
                if srv_name_part:
                    service = srv_name_part
                    version = srv_ver_part
            return {
                'port': port,
                'service': service,
                'version': version,
                'banner': http_profile.get("server") or "HTTPS Web Server",
                'confirmed': True,
                'http_profile': http_profile
            }
            
    return {
        'port': port,
        'service': service,
        'version': None,
        'banner': None,
        'confirmed': False
    }
