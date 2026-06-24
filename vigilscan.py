import sys
import time
import os
import datetime
import ipaddress
import socket
from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich.text import Text
from rich.table import Table
from rich.box import ASCII

# Load environment variables from .env file if it exists
def load_dotenv():
    paths = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "port_scanner", ".env")
    ]
    for env_path in paths:
        if os.path.exists(env_path):
            try:
                with open(env_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "=" in line:
                            key, val = line.split("=", 1)
                            val = val.strip().strip("'\"")
                            os.environ[key.strip()] = val
            except Exception:
                pass

load_dotenv()

from port_scanner.cli import parse_args
from port_scanner.core import resolve_target, run_port_scan, discover_hosts
from port_scanner.detector import detect_service
from port_scanner.nvd import NVDClient
from port_scanner.reporter import print_cli_report, export_json_report, export_html_report
from port_scanner.scoring import calculate_host_risk, get_cvss_severity, get_severity_color
from port_scanner.constants import PORT_SERVICE_MAP

def parse_targets(target_str):
    """
    Parses target input (IP, hostname, CIDR, or IP range) and returns a list
    of target IPs/hostnames along with a descriptive range string.
    """
    target_str = target_str.strip()
    
    # 1. CIDR notation (e.g., 192.168.29.0/24)
    if "/" in target_str:
        try:
            network = ipaddress.ip_network(target_str, strict=False)
            hosts = [str(ip) for ip in network.hosts()]
            if not hosts:
                # Handle /32 networks
                hosts = [str(network.network_address)]
            return hosts, target_str
        except ValueError:
            pass
            
    # 2. IP Range with Dash (e.g., 192.168.29.1-50)
    if "-" in target_str:
        try:
            start_str, end_str = target_str.split("-")
            start_str = start_str.strip()
            end_str = end_str.strip()
            
            if "." not in end_str:
                octets = start_str.split(".")
                if len(octets) == 4:
                    prefix = ".".join(octets[:3])
                    end_str = f"{prefix}.{end_str}"
                    
            start_ip = ipaddress.ip_address(start_str)
            end_ip = ipaddress.ip_address(end_str)
            
            if start_ip <= end_ip:
                start_int = int(start_ip)
                end_int = int(end_ip)
                # Safeguard: cap at 1024 IPs to prevent resource exhaustion
                limit = min(end_int - start_int + 1, 1024)
                hosts = [str(ipaddress.ip_address(start_int + i)) for i in range(limit)]
                return hosts, f"{start_str}-{end_str.split('.')[-1]}"
        except Exception:
            pass
            
    # 3. Single Hostname or IP
    resolved_ip = resolve_target(target_str)
    if resolved_ip:
        return [resolved_ip], target_str
        
    return [target_str], target_str

def main():
    console = Console(width=110)
    
    # Check if target was omitted entirely
    if len(sys.argv) == 1:
        console.print()
        console.print(Panel(
            Align.center(
                "[bold cyan]VIGILSCAN[/bold cyan]\n"
                "[dim]A Portfolio-grade Service & CVE Vulnerability Auditor[/dim]"
            ),
            border_style="cyan"
        ))
        console.print()
        console.print("[yellow]Usage Error:[/yellow] No target host was specified.")
        console.print("To see how this tool works and view all available options, please run:")
        console.print("  [bold cyan]python vigilscan.py --help[/bold cyan]\n")
        sys.exit(0)
        
    # 1. Parse Command Line Arguments
    args = parse_args()
    
    # Check privileges for Stealth Scan
    if getattr(args, "stealth_scan", False):
        import ctypes
        import os
        is_admin = False
        try:
            if hasattr(os, 'getuid'):
                is_admin = os.getuid() == 0
            else:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            pass
        if not is_admin:
            console.print("[bold yellow]![/bold yellow] Stealth SYN scan (-sS) requires Administrator/root privileges. Falling back to TCP Connect scan (-sT).\n")
            args.stealth_scan = False
            
    # Draw simple header
    console.print()
    console.print(Panel(
        Align.center(
            "[bold cyan]VIGILSCAN[/bold cyan]\n"
            "[dim]A Portfolio-grade Service & CVE Vulnerability Auditor[/dim]"
        ),
        border_style="cyan"
    ))
    console.print()
    
    # 2. Resolve Targets & Parse Subnets
    console.print(f"[bold blue]*[/bold blue] Resolving target input: [bold]{args.target}[/bold]...")
    targets, target_range = parse_targets(args.target)
    
    if not targets:
        console.print(f"[bold red]Error:[/bold red] Could not parse target or resolve host: '{args.target}'")
        sys.exit(1)
        
    # Print Scan Configuration Summary if verbose or aggressive scan is active
    if args.verbose >= 1 or getattr(args, "aggressive_scan", False):
        scan_mode = "TCP Stealth SYN (-sS)" if getattr(args, "stealth_scan", False) else "TCP Connect (-sT)"
        v_desc = "Standard Verbose" if args.verbose == 1 else "Detailed Verbose" if args.verbose == 2 else "Debug Verbose" if args.verbose >= 3 else "Quiet"
        
        config_text = (
            f"[bold cyan]Scan Summary & Settings:[/bold cyan]\n"
            f"  - Target Range: [bold]{target_range}[/bold] ({len(targets)} host{'s' if len(targets) > 1 else ''})\n"
            f"  - Port Range:   [bold]{args.ports}[/bold] ({len(args.ports_list)} port{'s' if len(args.ports_list) > 1 else ''})\n"
            f"  - Scan Engine:  [bold cyan]{scan_mode}[/bold cyan]\n"
            f"  - Timing Template: T{args.timing} (Threads: {args.threads}, Timeout: {args.timeout}s)\n"
            f"  - OS Detection (-O): {'[green]Enabled[/green]' if args.os_detection else '[dim]Disabled[/dim]'}\n"
            f"  - Version Audit (-sV): {'[green]Enabled[/green]' if args.version_scan else '[dim]Disabled[/dim]'}\n"
            f"  - Aggressive Shortcut (-A): {'[green]Active[/green]' if getattr(args, "aggressive_scan", False) else '[dim]Inactive[/dim]'}\n"
            f"  - Verbosity Level: [bold cyan]{args.verbose}[/bold cyan] ({v_desc})"
        )
        console.print(Panel(config_text, title="[bold white]VigilScan Settings[/bold white]", border_style="cyan", box=ASCII))
        console.print()
        
    # 3. Host Discovery (Ping Sweep)
    if getattr(args, "skip_discovery", False):
        alive_hosts = [(ip, True, None) for ip in targets]
    else:
        alive_hosts = discover_hosts(targets, args.threads, console)
        # Filter only active online hosts
        alive_hosts = [h for h in alive_hosts if h[1]]
    
    # 4. Handle Ping Scan Only flag (-sn)
    if args.ping_scan:
        console.print()
        console.print(Panel(
            Align.center(
                f"[bold white]PING SWEEP RESULTS FOR {target_range}[/bold white]\n"
                f"[dim]Hosts Scanned: {len(targets)} | Active Hosts: {len(alive_hosts)}[/dim]"
            ),
            box=ASCII,
            border_style="green"
        ))
        console.print()
        
        table = Table(box=ASCII, header_style="bold cyan")
        table.add_column("Host IP", style="bold white")
        table.add_column("Status", style="bold green")
        table.add_column("OS Guess (Ping TTL)", style="dim")
        
        for ip, is_alive, ttl in alive_hosts:
            os_guess = "Unknown"
            if ttl:
                if ttl <= 64:
                    os_guess = f"Linux / Unix (TTL={ttl})"
                elif ttl <= 128:
                    os_guess = f"Windows (TTL={ttl})"
                elif ttl <= 255:
                    os_guess = f"Network Device (TTL={ttl})"
            table.add_row(ip, "[green]Up[/green]", os_guess)
            
        console.print(table)
        console.print()
        sys.exit(0)
        
    # Check if we have active hosts
    if not alive_hosts:
        console.print(f"\n[bold yellow]Scan finished. All {len(targets)} targets appear to be offline.[/bold yellow]")
        console.print("[dim]Note: Host seems down. If it is really up, but blocking our ping probes, try scanning with -Pn (assume host is online).[/dim]\n")
        sys.exit(0)
        
    console.print(f"[bold green][+][/bold green] Host discovery complete: [bold]{len(alive_hosts)}/{len(targets)} hosts are online.[/bold]\n")
    
    start_time = time.time()
    hosts_results = []
    
    # Initialize NVD Client if version scanning is enabled
    nvd_client = None
    if args.version_scan:
        nvd_client = NVDClient(api_key=args.api_key)
        
    try:
        for ip, is_alive, ttl in alive_hosts:
            console.print(Panel(f"[bold white]Scanning Target: {ip}[/bold white]", box=ASCII, border_style="cyan"))
            
            # OS Guessing
            os_guess = None
            if args.os_detection:
                if ttl:
                    if ttl <= 64:
                        os_guess = f"Linux / Unix (TTL={ttl})"
                    elif ttl <= 128:
                        os_guess = f"Windows (TTL={ttl})"
                    elif ttl <= 255:
                        os_guess = f"Network Device (TTL={ttl})"
                else:
                    os_guess = "Unknown OS (No ping response TTL)"
                    
            # 5. Port Scan
            port_results = run_port_scan(
                ip=ip,
                ports_list=args.ports_list,
                threads=args.threads,
                timeout=args.timeout,
                console=console,
                verbose=args.verbose,
                stealth_scan=getattr(args, "stealth_scan", False),
                packet_trace=getattr(args, "packet_trace", False)
            )
            
            open_ports = [res["port"] for res in port_results if res["state"] == "Open"]
            
            if not port_results:
                console.print(f"  [yellow]No TCP ports found on {ip}[/yellow]\n")
                # Add host profile with zero open ports
                host_stats = {"total_open": 0, "vulnerable": 0, "severity_counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}}
                hosts_results.append({
                    "target": args.target if len(targets) == 1 else "",
                    "ip": ip,
                    "scan_time": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "elapsed_seconds": 0.0,
                    "host_risk_score": 0.0,
                    "host_severity": "Info",
                    "risk_color_hex": get_severity_color("Info")["hex"],
                    "stats": host_stats,
                    "findings": [],
                    "host_risk_details": {"s_max": 0.0, "s_others_sum": 0.0, "clean_ports": 0, "attack_surface_penalty": 0.0},
                    "os_info": os_guess
                })
                continue
                
            console.print(f"  [bold green][+][/bold green] Found {len(open_ports)} open TCP ports: {', '.join(map(str, open_ports))}")
            console.print()
            
            # 6. Service Detection & Banner Grabbing
            findings = []
            if open_ports:
                console.print(f"  [bold blue]*[/bold blue] Running service detection on {len(open_ports)} open ports...")
            
            for res in port_results:
                port = res["port"]
                state = res["state"]
                
                if state != "Open":
                    # For Closed or Filtered ports, skip service detection and CVE lookups
                    findings.append({
                        "port": port,
                        "protocol": "TCP",
                        "service": PORT_SERVICE_MAP.get(port, "Unknown"),
                        "version": None,
                        "banner": None,
                        "confirmed": False,
                        "state": state,
                        "cves": []
                    })
                    continue
                
                # Active service detection for open ports
                if args.version_scan:
                    # Version scan enabled: Grab banners and request NVD details
                    service_info = detect_service(ip, port, args.timeout)
                    srv_name = service_info['service']
                    srv_ver = service_info['version']
                    confirmed_status = "confirmed" if service_info['confirmed'] else "open"
                    
                    display_ver = f" v{srv_ver}" if srv_ver else ""
                    console.print(f"    - Port {port}: [cyan]{srv_name}{display_ver}[/cyan] ({confirmed_status})")
                    
                    cves = []
                    if srv_ver:
                        cves = nvd_client.lookup_cves(srv_name, srv_ver, console=console, verbose=args.verbose)
                        if cves:
                            console.print(f"      [bold red]->[/bold red] Found {len(cves)} potential CVE matches (highest CVSS: {cves[0]['score']})")
                        else:
                            console.print("      [dim]-> No CVE matches found.[/dim]")
                    else:
                        console.print("      [dim]-> No version detected. Skipping CVE lookup.[/dim]")
                else:
                    # Fast scan: Skip banner grabbing, map using local dictionary
                    srv_name = PORT_SERVICE_MAP.get(port, "Unknown")
                    service_info = {
                        "port": port,
                        "protocol": "TCP",
                        "service": srv_name,
                        "version": None,
                        "banner": None,
                        "confirmed": False
                    }
                    cves = []
                    console.print(f"    - Port {port}: [cyan]{srv_name}[/cyan] (open)")
                    
                service_info['cves'] = cves
                service_info['state'] = "Open"
                findings.append(service_info)
                
            # Perform OS guessing checks based on service banners if TTL OS Guess is Linux/Unix
            if args.os_detection and os_guess:
                for f in findings:
                    banner = f.get("banner", "") or ""
                    if "ubuntu" in banner.lower() or "debian" in banner.lower() or "centos" in banner.lower():
                        os_guess = f"Linux ({banner.split()[0]})"
                        break
                    elif "microsoft" in banner.lower() or "windows" in banner.lower():
                        os_guess = "Microsoft Windows Server"
                        break
                        
            # Calculate Risk Scoring
            host_risk_score, host_severity = calculate_host_risk(findings)
            risk_color_hex = get_severity_color(host_severity)["hex"]
            
            # Print individual CLI report
            print_cli_report(
                args.target if len(targets) == 1 else ip,
                ip,
                time.time() - start_time,
                findings,
                console,
                os_guess,
                show_only_open=getattr(args, "show_only_open", False)
            )
            
            # Format host statistics
            # Format host statistics
            stats_vulnerable = sum(1 for f in findings if f.get("cves"))
            severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
            
            for f in findings:
                state = f.get("state", "Open")
                if state in ("Closed", "Filtered"):
                    continue
                host_cves = f.get("cves", [])
                if host_cves:
                    for cve in host_cves:
                        sev = get_cvss_severity(cve["score"])
                        severity_counts[sev] += 1
                else:
                    severity_counts["Info"] += 1
                    
            # Calculate breakdown metrics
            port_max_scores = []
            clean_ports = 0
            for f in findings:
                state = f.get("state", "Open")
                if state in ("Closed", "Filtered"):
                    continue
                host_cves = f.get("cves", [])
                if host_cves:
                    port_max_scores.append(max(c["score"] for c in host_cves))
                else:
                    clean_ports += 1
            s_max = max(port_max_scores) if port_max_scores else 0.0
            s_others_sum = sum(sorted(port_max_scores, reverse=True)[1:]) if len(port_max_scores) > 1 else 0.0
            attack_surface_penalty = min(1.0, 0.05 * clean_ports)
            
            hosts_results.append({
                "target": args.target if len(targets) == 1 else "",
                "ip": ip,
                "scan_time": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "elapsed_seconds": round(time.time() - start_time, 2),
                "host_risk_score": host_risk_score,
                "host_severity": host_severity,
                "risk_color_hex": risk_color_hex,
                "stats": {
                    "total_open": len(findings),
                    "vulnerable": stats_vulnerable,
                    "severity_counts": severity_counts
                },
                "findings": findings,
                "host_risk_details": {
                    "s_max": round(s_max, 1),
                    "s_others_sum": round(s_others_sum, 1),
                    "clean_ports": clean_ports,
                    "attack_surface_penalty": round(attack_surface_penalty, 2)
                },
                "os_info": os_guess
            })
            
        total_elapsed = time.time() - start_time
        
        # 7. File Exporters
        show_only_open = getattr(args, "show_only_open", False)
        if args.output_all:
            json_path = f"{args.output_all}.json"
            html_path = f"{args.output_all}.html"
            console.print(f"[bold blue]*[/bold blue] Exporting consolidated reports under prefix: [bold]{args.output_all}[/bold]...")
            export_json_report(json_path, target_range, hosts_results, total_elapsed, show_only_open=show_only_open)
            export_html_report(html_path, target_range, hosts_results, total_elapsed, show_only_open=show_only_open)
            console.print("[bold green][+] Export complete (.json and .html generated).[/bold green]\n")
        else:
            if args.json:
                console.print(f"[bold blue]*[/bold blue] Exporting JSON report to: [bold]{args.json}[/bold]...")
                export_json_report(args.json, target_range, hosts_results, total_elapsed, show_only_open=show_only_open)
                console.print("[bold green][+] JSON export complete.[/bold green]\n")
            if args.html:
                console.print(f"[bold blue]*[/bold blue] Exporting HTML dashboard to: [bold]{args.html}[/bold]...")
                export_html_report(args.html, target_range, hosts_results, total_elapsed, show_only_open=show_only_open)
                console.print("[bold green][+] HTML export complete.[/bold green]\n")
                
    except KeyboardInterrupt:
        console.print("\n[bold red]![/bold red] Scan interrupted by user. Exiting...")
    finally:
        # Close SQLite connections
        if nvd_client:
            nvd_client.close()

if __name__ == '__main__':
    main()
