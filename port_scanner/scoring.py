def get_cvss_severity(score):
    """
    Map CVSS base score (0.0 to 10.0) to standard qualitative severity labels.
    """
    if score <= 0.0:
        return "Info"
    elif 0.1 <= score <= 3.9:
        return "Low"
    elif 4.0 <= score <= 6.9:
        return "Medium"
    elif 7.0 <= score <= 8.9:
        return "High"
    else:  # 9.0 to 10.0
        return "Critical"

def get_severity_color(severity):
    """
    Returns the rich and CSS color hex for each severity tier.
    """
    colors = {
        "Info": {"rich": "blue", "hex": "#3b82f6"},
        "Low": {"rich": "green", "hex": "#10b981"},
        "Medium": {"rich": "yellow", "hex": "#f59e0b"},
        "High": {"rich": "red", "hex": "#ef4444"},
        "Critical": {"rich": "bold red", "hex": "#b91c1c"}
    }
    return colors.get(severity, {"rich": "white", "hex": "#ffffff"})

def calculate_host_risk(findings):
    """
    Compute a defensible overall host risk score based on scanned findings.
    
    Formula:
      R = min(10.0, S_max + 0.1 * Sum(S_i) + min(1.0, 0.05 * N_clean))
      
    Where:
      - S_max: Highest CVSS score found across all open ports.
      - S_i: CVSS scores of remaining vulnerabilities (capped at the max per port).
      - N_clean: Number of open ports with no identified vulnerabilities.
      
    Justification:
      1. Baseline Severity (S_max): A system is only as secure as its weakest point.
         The highest vulnerability score is the logical baseline for host risk.
      2. Compounding Vulnerabilities (0.1 * Sum(S_i)): Multiple vulnerabilities
         exponentially increase risk. Attackers can pivot or exploit different avenues.
         Adding 10% of other vulnerability scores captures this threat.
      3. Attack Surface Penalty (0.05 * N_clean): Even if no known CVE is found
         in a banner, an open port increases attack surface (zero-days, recon, brute force).
         We add 0.05 per clean port, capped at 1.0, so that clean hosts remain 'Low' risk.
      4. Cap (10.0): The score is capped at 10.0 to match the standard CVSS scale.
    """
    if not findings:
        return 0.0, "Info"
        
    # Extract maximum CVSS score per port
    port_max_scores = []
    clean_ports_count = 0
    
    for f in findings:
        # Only count Open/Confirmed ports for risk calculation
        state = f.get("state", "Open")
        if state in ("Closed", "Filtered"):
            continue
            
        cves = f.get("cves", [])
        if cves:
            # Get the highest CVE score on this port
            max_cve_score = max(c.get("score", 0.0) for c in cves)
            port_max_scores.append(max_cve_score)
        else:
            clean_ports_count += 1
            
    if not port_max_scores:
        # No vulnerabilities found, risk score based only on open ports
        score = min(1.0, 0.05 * clean_ports_count)
        return round(score, 1), get_cvss_severity(score)
        
    # Sort port maximums descending
    port_max_scores.sort(reverse=True)
    s_max = port_max_scores[0]
    s_others = port_max_scores[1:]
    
    # Sum compounding vulnerabilities (10% of each remaining port's max score)
    compounding_factor = 0.1 * sum(s_others)
    
    # Attack surface penalty (capped at 1.0)
    attack_surface_penalty = min(1.0, 0.05 * clean_ports_count)
    
    total_score = s_max + compounding_factor + attack_surface_penalty
    total_score = min(10.0, total_score)
    
    return round(total_score, 1), get_cvss_severity(total_score)
