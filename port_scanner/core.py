import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

def resolve_target(hostname):
    """
    Resolve hostname to IP. If already an IP, it returns the IP.
    Returns None on failure.
    """
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except socket.gaierror:
        return None

import errno

def scan_port_syn(ip, port, timeout, packet_trace=False):
    """
    Attempt to run a TCP SYN Stealth scan on a single port using Scapy.
    """
    try:
        from scapy.all import IP, TCP, sr1, send
        
        if packet_trace:
            print(f"[TRACE] Sending TCP SYN packet to {ip}:{port}")
            
        packet = IP(dst=ip)/TCP(dport=port, flags="S")
        response = sr1(packet, timeout=timeout, verbose=0)
        
        if response is None:
            if packet_trace:
                print(f"[TRACE] No response from {ip}:{port} (Filtered)")
            return "Filtered"
            
        if response.haslayer(TCP):
            tcp_layer = response.getlayer(TCP)
            if tcp_layer.flags == 0x12:  # SYN-ACK
                if packet_trace:
                    print(f"[TRACE] Received TCP SYN-ACK from {ip}:{port} (Open)")
                # Send RST to tear down connection politely and close the half-open port
                sport = tcp_layer.dport
                seq = tcp_layer.ack
                rst_packet = IP(dst=ip)/TCP(sport=sport, dport=port, seq=seq, flags="R")
                send(rst_packet, verbose=0)
                return "Open"
            elif tcp_layer.flags == 0x14 or tcp_layer.flags == 0x12 | 0x04:  # RST-ACK or RST
                if packet_trace:
                    print(f"[TRACE] Received TCP RST from {ip}:{port} (Closed)")
                return "Closed"
                
        if packet_trace:
            print(f"[TRACE] Received unexpected packet response from {ip}:{port} (Filtered)")
        return "Filtered"
    except Exception as e:
        if packet_trace:
            print(f"[TRACE] Error in SYN scan on {ip}:{port}: {str(e)}")
        raise e

def scan_port(ip, port, timeout, packet_trace=False, stealth_scan=False):
    """
    Perform a port scan on a single port.
    Supports TCP Connect scan (default) and TCP SYN scan (stealth).
    Returns (port, state) where state is Open, Closed, or Filtered.
    """
    if stealth_scan:
        try:
            state = scan_port_syn(ip, port, timeout, packet_trace)
            return port, state
        except Exception:
            # Fallback to connect scan
            pass
            
    # Standard TCP Connect Scan
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    if packet_trace:
        print(f"[TRACE] Initiating TCP Connect (handshake) to {ip}:{port}")
    try:
        result = s.connect_ex((ip, port))
        if result == 0:
            if packet_trace:
                print(f"[TRACE] TCP Connection successful to {ip}:{port} (Open)")
            return port, "Open"
        elif result in (111, 10061, errno.ECONNREFUSED):
            if packet_trace:
                print(f"[TRACE] TCP Connection refused on {ip}:{port} (Closed)")
            return port, "Closed"
        else:
            if packet_trace:
                print(f"[TRACE] TCP Connection returned code {result} on {ip}:{port} (Filtered)")
            return port, "Filtered"
    except Exception as e:
        if packet_trace:
            print(f"[TRACE] TCP Connection raised exception on {ip}:{port} - {str(e)} (Filtered)")
        return port, "Filtered"
    finally:
        try:
            s.close()
        except Exception:
            pass
    return port, "Filtered"

import os
import re
import platform
import subprocess

def ping_host(ip):
    """
    Ping a host to check if it is alive and extract TTL.
    Returns (is_alive, ttl)
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    # Timeout parameter: -w 1000 (Windows, 1000ms) or -W 1 (Linux, 1s)
    timeout_param = ['-w', '1000'] if platform.system().lower() == 'windows' else ['-W', '1']
    
    command = ['ping', param, '1'] + timeout_param + [ip]
    try:
        res = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3.0)
        output = res.stdout
        
        # Check for TTL in the output to confirm an active reply
        ttl_match = re.search(r"ttl=(\d+)", output, re.IGNORECASE)
        if ttl_match:
            return True, int(ttl_match.group(1))
        
        # Fallback checks (e.g. if TTL is not printed but packet is received successfully)
        if res.returncode == 0:
            if "received = 1" in output.lower() or "1 received" in output.lower() or "1 packets received" in output.lower():
                return True, None
        
        return False, None
    except Exception:
        return False, None

def ip_key(ip):
    try:
        return [int(x) for x in ip.split('.')]
    except ValueError:
        return [0, 0, 0, 0]

def discover_hosts(ips_list, threads, console):
    """
    Ping scan a list of IPs in parallel.
    Returns a list of tuples: (ip, is_alive, ttl)
    """
    alive_hosts = []
    num_workers = min(threads, len(ips_list))
    
    if len(ips_list) <= 1:
        # Single host ping scan without progress bar
        ip = ips_list[0]
        is_alive, ttl = ping_host(ip)
        return [(ip, is_alive, ttl)]
        
    console.print(f"[bold blue]*[/bold blue] Running ping sweep (host discovery) across {len(ips_list)} targets...")
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("({task.completed}/{task.total} hosts)"),
        console=console
    ) as progress:
        task = progress.add_task("Pinging...", total=len(ips_list))
        
        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = {executor.submit(ping_host, ip): ip for ip in ips_list}
            
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    is_alive, ttl = future.result()
                    if is_alive:
                        alive_hosts.append((ip, is_alive, ttl))
                except Exception:
                    pass
                finally:
                    progress.update(task, advance=1)
                    
    # Return sorted alive hosts
    return sorted(alive_hosts, key=lambda x: ip_key(x[0]))

def run_port_scan(ip, ports_list, threads, timeout, console, verbose=False, stealth_scan=False, packet_trace=False):
    """
    Run multithreaded TCP connect or stealth SYN scan over list of ports.
    Displays a beautiful rich progress bar.
    Returns a list of dicts with port scan results: [{'port': p, 'state': s}].
    """
    port_results = []
    
    scan_type = "TCP SYN stealth" if stealth_scan else "TCP connect"
    console.print(f"[bold blue]*[/bold blue] Initializing {scan_type} scan against {ip} for {len(ports_list)} ports...")
    
    # Using rich progress bar
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("({task.completed}/{task.total} ports)"),
        console=console
    ) as progress:
        
        task = progress.add_task("Scanning...", total=len(ports_list))
        
        # Limit worker threads to max of number of ports or user config
        num_workers = min(threads, len(ports_list))
        
        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            # Submit all scan jobs
            futures = {executor.submit(scan_port, ip, p, timeout, packet_trace, stealth_scan): p for p in ports_list}
            
            for future in as_completed(futures):
                p = futures[future]
                try:
                    port, state = future.result()
                    port_results.append({"port": port, "state": state})
                    v_level = 1 if verbose is True else (int(verbose) if verbose else 0)
                    if v_level >= 1 and state == "Open":
                        console.print(f"  [green][+][/green] Discovered open port [bold cyan]{port}/TCP[/bold cyan] on [bold]{ip}[/bold]")
                    elif v_level >= 2 and state == "Closed":
                        console.print(f"  [red][-][/red] Discovered closed port [bold cyan]{port}/TCP[/bold cyan] on [bold]{ip}[/bold]")
                    elif v_level >= 3 and state == "Filtered":
                        console.print(f"  [yellow][?][/yellow] Discovered filtered port [bold cyan]{port}/TCP[/bold cyan] on [bold]{ip}[/bold]")
                except Exception as e:
                    console.print(f"[red]Error scanning port {p}: {str(e)}[/red]")
                finally:
                    progress.update(task, advance=1)
                    
    # Return sorted list of port results
    return sorted(port_results, key=lambda x: x["port"])
