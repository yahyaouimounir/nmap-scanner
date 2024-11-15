import gradio as gr
import nmap
import re
from datetime import datetime

# Function to parse IP input formats
def parse_ip_input(ip_input):
    # Regex patterns for different IP input formats
    cidr_pattern = r"(\d+\.\d+\.\d+\.\d+)(/\d+)"
    range_pattern = r"(\d+\.\d+\.\d+\.\d+)-(\d+)"
    full_range_pattern = r"(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)"
    
    # Check CIDR notation (e.g., 192.168.0.1/24)
    cidr_match = re.match(cidr_pattern, ip_input)
    if cidr_match:
        return ip_input  # Return the entire CIDR notation (e.g., 192.168.0.1/24)

    # Check range format (e.g., 192.168.0.1-150)
    range_match = re.match(range_pattern, ip_input)
    if range_match:
        ip_start = range_match.group(1)
        ip_end = range_match.group(2)
        return ip_start + '-' + ip_end

    # Check full IP range (e.g., 192.168.0.1-192.168.0.150)
    full_range_match = re.match(full_range_pattern, ip_input)
    if full_range_match:
        ip_start = full_range_match.group(1)
        ip_end = full_range_match.group(2)
        return ip_start + '-' + ip_end

    # Otherwise, return single IP
    return ip_input

# Function to perform the scan using nmap
def scan_ip(ip_input, scan_type, port, os_discovery, verbose_level):
    ip_range = parse_ip_input(ip_input)
    
    # Initialize the nmap scanner
    scanner = nmap.PortScanner()

    # Dictionary of scan types with additional options
    scan_types = {
        'TCP Connect Scan': '-sT -T5',
        'TCP SYN Scan': '-sS -T5', 
        'UDP Scan': '-sU -T5',
        'Ping Scan': '-sn -T5',
        'Aggressive Scan': '-A -T5', 
        'No Ping Scan': '-Pn -T5'  
    }

    #  scan arguments based on user input
    scan_option = scan_types.get(scan_type, '-sT')
    if os_discovery:
        scan_option += ' -O'
    if verbose_level == "Verbose":
        scan_option += ' -v'
    elif verbose_level == "Verbose Level 2":
        scan_option += ' -vv'
    
  

    # Add port-specific option if provided
    port_range = port if port else '1-1024'  # Default to first 1024 ports

    try:
        # Scan the specified range or IP (including CIDR ranges)
        scanner.scan(hosts=ip_range, ports=port_range, arguments=scan_option)

        # ************************************** Output ************************************
        scan_results = f"Starting Nmap at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"

        # Add host report
        for host in scanner.all_hosts():
            scan_results += f"\nNmap scan report for {scanner[host].hostname()} ({host})\n"  
            scan_results += f"Host is up \n"
            scan_results += f"PORT     STATE    SERVICE\n"      
            # Add ports to the report
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in ports:
                    state = scanner[host][proto][port]['state']
                    service = scanner[host][proto][port].get('name', 'unknown')
                    version = scanner[host][proto][port].get('version', 'N/A')  
                    scan_results += f"{port}/tcp  {state}     {service} {version}\n"  

            # Add OS detection if requested
            if os_discovery and 'osmatch' in scanner[host] and scanner[host]['osmatch']:
                best_os_match = max(scanner[host]['osmatch'], key=lambda x: int(x['accuracy']))
                scan_results += f"\nOS Detection:\nMost likely OS: {best_os_match['name']} (Accuracy: {best_os_match['accuracy']}%)\n"
            else:
                scan_results += "\nOS Detection: Not available\n"
            
            # If scan type is Aggressive, include additional details:
            if scan_type == "Aggressive Scan":
                # Display traceroute (if available)
                if 'trace' in scanner[host]:
                    scan_results += f"\nTraceroute:\n{scanner[host]['trace']}\n"
                
                # Display script scan results (if available)
                if 'hostscript' in scanner[host]:
                    scan_results += "\nNmap Script Scan Results:\n"
                    for script in scanner[host]['hostscript']:
                        scan_results += f"Script: {script['id']} - {script['output']}\n"

        # Add end of scan message
        scan_results += f"\nNmap done: {len(scanner.all_hosts())} IP addresses ({len(scanner.all_hosts())} hosts up) scanned\n"

        return scan_results  

    except Exception as e:
        return f" scan error : {str(e)}"

# =======================================  Gradio web interface  ====================================================

iface = gr.Interface(
    fn=scan_ip,  # Calling the function to scan
    inputs=[
        gr.Textbox(label="IP address", placeholder="Ex: 192.168.0.1, 192.168.0.1/24, 192.168.0.1-150, etc."),
        gr.Dropdown(
            label="Scan Type",
            choices=[
                'TCP Connect Scan', 
                'TCP SYN Scan',    
                'UDP Scan', 
                'Ping Scan', 
                'Aggressive Scan',
                'No Ping Scan'      
            ],
            value='TCP Connect Scan',  
            type="value"
        ),
        gr.Textbox(label="Port", placeholder="Ex: 80, 22, or 1-1024"),
        gr.Checkbox(label="Enable OS Discovery", value=False),
        gr.Dropdown(
            label="Verbose Level",
            choices=["None", "Verbose", "Verbose Level 2"],
            value="None",
            type="value"
        )
    ],
    outputs=[
        gr.Textbox(label="Scan Result"),
    ],
    title="Port Scanner with Nmap",
    description="Enter IP address, choose scan type, port, and additional options.",

)

# Launch the interface
iface.launch(server_name="0.0.0.0", server_port=5000,inline=True)
