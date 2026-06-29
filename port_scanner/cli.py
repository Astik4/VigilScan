import argparse
import os
from port_scanner.constants import TOP_100_PORTS, TOP_1000_PORTS

def parse_ports(ports_str):
    """
    Parse a ports string which can be a preset ('top100', 'top1000'),
    a range ('1-1024'), a comma-separated list ('22,80,443'), or combinations.
    Supports Nmap style:
    - '-p-' (or just '-') for all ports 1-65535
    - '-p 22-' for 22 to 65535
    - '-p -80' for 1 to 80
    """
    ports_str = ports_str.strip()
    
    # Handle '-' or 'all' to scan all ports
    if ports_str == '-' or ports_str.lower() == 'all':
        return list(range(1, 65536))
    if ports_str.lower() == 'top100':
        return TOP_100_PORTS
    if ports_str.lower() == 'top1000':
        return TOP_1000_PORTS
        
    ports = set()
    for part in ports_str.split(','):
        part = part.strip()
        if not part:
            continue
            
        if part == '-':
            ports.update(range(1, 65536))
            continue
            
        if '-' in part:
            try:
                # Handle cases like 22- (22 to 65535) or -80 (1 to 80)
                if part.startswith('-'):
                    start = 1
                    end_str = part[1:]
                    end = int(end_str.strip())
                elif part.endswith('-'):
                    start_str = part[:-1]
                    start = int(start_str.strip())
                    end = 65535
                else:
                    start_str, end_str = part.split('-')
                    start = int(start_str.strip())
                    end = int(end_str.strip())
                
                if 1 <= start <= 65535 and 1 <= end <= 65535:
                    if start <= end:
                        ports.update(range(start, end + 1))
                    else:
                        ports.update(range(end, start + 1))
                else:
                    raise argparse.ArgumentTypeError(f"Port range out of bounds (1-65535): {part}")
            except ValueError:
                raise argparse.ArgumentTypeError(f"Invalid port range format: {part}")
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
                else:
                    raise argparse.ArgumentTypeError(f"Port out of bounds (1-65535): {p}")
            except ValueError:
                raise argparse.ArgumentTypeError(f"Invalid port number: {part}")
                
    if not ports:
        raise argparse.ArgumentTypeError(f"No valid ports could be parsed from: {ports_str}")
        
    return sorted(list(ports))

def get_parser():
    parser = argparse.ArgumentParser(
        description="Risk-Scoring Port Scanner - A security audit tool that scans ports, detects services, matches NVD CVEs, and scores host risk.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Target host (positional, required - Nmap style)
    parser.add_argument(
        'target',
        help="Target hostname or IP address to scan (e.g., '127.0.0.1', 'scanme.nmap.org')"
    )
    
    parser.add_argument(
        '-p',
        default=None,
        dest='ports',
        help="Ports to scan (default: 'top1000', or 'top100' if -F is specified). Options:\n"
             "  - 'top100': scans 100 most common TCP ports\n"
             "  - 'top1000': scans 1000 common TCP ports (well-known 1-1024 + selected high)\n"
             "  - Nmap-style: list (e.g. '22,80,443'), ranges ('1-1024', '80-', '-80'), or '-' for all ports"
    )
    
    # Basic Nmap Scan Toggles
    parser.add_argument(
        '-sT',
        action='store_true',
        dest='connect_scan',
        help="TCP Connect Scan (default behavior)"
    )
    
    parser.add_argument(
        '-sS',
        action='store_true',
        dest='stealth_scan',
        help="Stealth SYN Scan (requires root/admin privileges)"
    )
    
    parser.add_argument(
        '-Pn',
        action='store_true',
        dest='skip_discovery',
        help="Skip host discovery - assume all target hosts are online"
    )
    
    parser.add_argument(
        '--open',
        action='store_true',
        dest='show_only_open',
        help="Only display open and confirmed ports in reports"
    )
    
    parser.add_argument(
        '--packet-trace',
        action='store_true',
        dest='packet_trace',
        help="Enable diagnostic packet/socket trace output"
    )
    
    parser.add_argument(
        '-sV',
        action='store_true',
        dest='version_scan',
        help="Enable service version detection and NVD vulnerability audit"
    )
    
    parser.add_argument(
        '-sn',
        action='store_true',
        dest='ping_scan',
        help="Ping scan - Host discovery only (skip port scan)"
    )
    
    parser.add_argument(
        '-F',
        action='store_true',
        dest='fast_scan',
        help="Fast scan - scan the top 100 ports instead of top 1000"
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        dest='verbose',
        help="Verbose mode - specify multiple times for more verbosity:\n"
             "  -v:   Print open ports as they are discovered\n"
             "  -vv:  Print open/closed ports and enable connection packet tracing\n"
             "  -vvv: Print open/closed/filtered ports, trace connections, and log detailed NVD API endpoints/caching details"
    )
    
    parser.add_argument(
        '-O',
        action='store_true',
        dest='os_detection',
        help="OS detection - guess target OS based on TTL and version banners"
    )
    
    parser.add_argument(
        '-A',
        action='store_true',
        dest='aggressive_scan',
        help="Aggressive scan template - enable OS detection (-O), service version detection (-sV),\n"
             "web app fingerprinter (script scan), and automatically set verbosity to level 1 (or higher)"
    )
    
    # Nmap-Style Timing Template
    parser.add_argument(
        '-T',
        type=int,
        choices=[1, 2, 3, 4, 5],
        default=4,
        dest='timing',
        help="Timing template (1-5) for automatic performance tuning (default: 4)\n"
             "  - 1: Sneaky (1 thread, 5.0s timeout)\n"
             "  - 2: Polite (5 threads, 3.0s timeout)\n"
             "  - 3: Normal (30 threads, 1.5s timeout)\n"
             "  - 4: Aggressive (100 threads, 1.0s timeout)\n"
             "  - 5: Insane (200 threads, 0.5s timeout)"
    )
    
    # Override threads/timeout directly if needed
    parser.add_argument(
        '-th', '--threads',
        type=int,
        default=None,
        help="Number of concurrent scanning threads (Overrides -T)"
    )
    
    parser.add_argument(
        '-to', '--timeout',
        type=float,
        default=None,
        help="Timeout in seconds for port connections (Overrides -T)"
    )
    
    # Nmap-Style Output formats
    parser.add_argument(
        '-oA',
        default=None,
        dest='output_all',
        help="Export reports in ALL formats (JSON & HTML) using the specified prefix"
    )
    
    parser.add_argument(
        '-oJ',
        default=None,
        dest='json',
        help="Export report in JSON format to the specified filepath"
    )
    
    parser.add_argument(
        '-oH',
        default=None,
        dest='html',
        help="Export report in HTML format to the specified filepath"
    )
    
    return parser

def parse_args():
    parser = get_parser()
    args = parser.parse_args()
    
    # Resolve default ports if not specified by user
    if args.ports is None:
        if args.fast_scan:
            args.ports = 'top100'
        else:
            args.ports = 'top1000'
            
    # Post-parsing ports list validation
    try:
        args.ports_list = parse_ports(args.ports)
    except argparse.ArgumentTypeError as e:
        parser.error(str(e))
        
    # Apply timing template settings (nmap timing style)
    timing_templates = {
        1: {"threads": 1, "timeout": 5.0},
        2: {"threads": 5, "timeout": 3.0},
        3: {"threads": 30, "timeout": 1.5},
        4: {"threads": 100, "timeout": 1.0},
        5: {"threads": 200, "timeout": 0.5}
    }
    
    template = timing_templates[args.timing]
    
    # Use template defaults unless explicitly overridden by user
    if args.threads is None:
        args.threads = template["threads"]
    if args.timeout is None:
        args.timeout = template["timeout"]
        
    # Validations on overrides
    if args.threads <= 0:
        parser.error("Thread count must be a positive integer.")
    if args.timeout <= 0:
        parser.error("Timeout must be a positive number.")
        
    # Resolve NVD API Key from env var fallback (.env loaded inside scanner.py)
    args.api_key = os.environ.get('NVD_API_KEY', None)
    
    # Apply aggressive scan shortcut flags
    if getattr(args, "aggressive_scan", False):
        args.version_scan = True
        args.os_detection = True
        if args.verbose == 0:
            args.verbose = 1
            
    # Map high verbosity levels (e.g. -vv or -vvv) to automatically enable packet trace
    if args.verbose >= 2:
        args.packet_trace = True
        
    return args
