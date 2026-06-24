import re
import socket
import ssl
import requests
import urllib3
from cryptography import x509

# Suppress insecure connection warnings for scanning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_ssl_details(ip, port, timeout):
    """
    Establish an SSL connection to the target port, fetch the raw DER certificate,
    and parse it using cryptography to extract Issuer, Subject, and Validity dates.
    Works for both verified and self-signed certificates.
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                if not cert_der:
                    return None
                
                cert = x509.load_der_x509_certificate(cert_der)
                
                # Extract Common Names (CN)
                subject_cn = "Unknown"
                for attr in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME):
                    subject_cn = attr.value
                    
                issuer_cn = "Unknown"
                for attr in cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME):
                    issuer_cn = attr.value
                    
                not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before
                not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after
                
                return {
                    "subject": subject_cn,
                    "issuer": issuer_cn,
                    "not_before": not_before.strftime('%Y-%m-%d %H:%M:%S'),
                    "not_after": not_after.strftime('%Y-%m-%d %H:%M:%S')
                }
    except Exception:
        pass
    return None

def fingerprint_http(ip, port, timeout, is_ssl=False):
    """
    Queries the target HTTP/HTTPS server, extracts headers, parses HTML body,
    detects technologies, and gathers SSL/TLS details if applicable.
    """
    protocol = "https" if is_ssl else "http"
    url = f"{protocol}://{ip}:{port}/"
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) VigilScan/1.0'
    }
    
    profile = {
        "title": "Unknown",
        "server": None,
        "techs": [],
        "ssl": None,
        "headers": {}
    }
    
    # 1. Attempt connection and fetch headers/body
    try:
        response = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
        # Store important headers
        for h in ['Server', 'X-Powered-By', 'X-AspNet-Version']:
            if h in response.headers:
                profile["headers"][h] = response.headers[h]
        
        # Extract Server header
        profile["server"] = response.headers.get("Server")
        
        # Limit body search to first 50KB to conserve memory/time
        body = response.text[:50000]
        
        # 2. Extract HTML Page Title
        title_match = re.search(r'<title>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
        if title_match:
            profile["title"] = title_match.group(1).strip()
            
    except requests.RequestException:
        # If connection fails (e.g. timeout or connection reset), return empty
        return None

    # 3. Analyze headers and body for technology signatures
    detected_techs = set()
    
    # --- Header Signatures ---
    x_powered_by = response.headers.get("X-Powered-By", "").lower()
    server = (profile["server"] or "").lower()
    
    # PHP
    if "php" in x_powered_by or "phpsessid" in response.cookies:
        detected_techs.add("PHP")
    # ASP.NET
    if "asp.net" in x_powered_by or "x-aspnet-version" in response.headers or "asp.net_sessionid" in response.cookies:
        detected_techs.add("ASP.NET")
    # Express / Node.js
    if "express" in x_powered_by or "connect.sid" in response.cookies:
        detected_techs.add("Express")
    # Laravel
    if "laravel_session" in response.cookies:
        detected_techs.add("Laravel")
    # Django
    if "csrftoken" in response.cookies:
        detected_techs.add("Django")
    # Web Servers
    if "apache" in server:
        detected_techs.add("Apache")
    elif "nginx" in server:
        detected_techs.add("Nginx")
    elif "microsoft-iis" in server:
        detected_techs.add("IIS")
    elif "litespeed" in server:
        detected_techs.add("LiteSpeed")
        
    # --- HTML Body Signatures ---
    body_lower = body.lower()
    
    # WordPress
    if "wp-content" in body_lower or "wp-includes" in body_lower or re.search(r'<meta name="generator" content="wordpress', body_lower):
        detected_techs.add("WordPress")
    # Joomla
    if "joomla" in body_lower or re.search(r'<meta name="generator" content="joomla', body_lower):
        detected_techs.add("Joomla")
    # Drupal
    if "drupal.settings" in body_lower or "sites/all/themes" in body_lower or re.search(r'<meta name="generator" content="drupal', body_lower):
        detected_techs.add("Drupal")
    # Next.js
    if "__next_data__" in body_lower or "_next/static" in body_lower:
        detected_techs.add("Next.js")
    # React
    if "data-reactroot" in body_lower or "react-root" in body_lower:
        detected_techs.add("React")
    # Vue.js
    if "data-v-" in body_lower or "vue.js" in body_lower:
        detected_techs.add("Vue.js")
    # jQuery
    if "jquery.min.js" in body_lower or "jquery.js" in body_lower or "jquery-" in body_lower:
        detected_techs.add("jQuery")
    # Bootstrap
    if "bootstrap.min.css" in body_lower or "bootstrap.min.js" in body_lower or "bootstrap.css" in body_lower:
        detected_techs.add("Bootstrap")
        
    profile["techs"] = sorted(list(detected_techs))
    
    # 4. Extract SSL Details
    if is_ssl:
        profile["ssl"] = get_ssl_details(ip, port, timeout)
        
    return profile
