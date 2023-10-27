#!/usr/bin/env python3

# Python Standard Library Modules and Classes
import signal                 # Signal handling
import os                     # Operating System interfaces 
import re                     # Regular expression operations
import time                   # Time-related functions
import subprocess             # Subprocess management
import sys                    # System-specific parameters and functions
from threading import Thread  # Thread-based parallelism
import socket                 # Socket Module Import
import validators             # Data Validation
import readline               # Command-line editing library
import threading              # Thread Management

# Colors
# Define various color codes for better visualization in the terminal
Red = '\033[31m'
Green = '\033[32m'
Yellow = '\033[33m'
Blue = '\033[34m'
Magenta = '\033[35m'
Cyan = '\033[36m'
White = '\033[97m'

# Console Text Effects
Reverse = '\033[7m'
Bold = '\033[1m'
Underline = '\033[4m'
Blink = '\033[5m'

# Reset text and color style to default
Reset = '\033[0m'

# Starting script...
print(f"{Cyan}Starting script...{Reset}")

# Ctrl+C
# Function to handle the interrupt signal (Ctrl+C)
def ctrl_c(sig, frame):
    print(f"\n{Red}[!] Interrupt detected. Exiting the script...{Reset}")
    exit(0)
    
# Set up the keyboard interrupt handler
signal.signal(signal.SIGINT, ctrl_c)

# Hidden script
# Function to display additional Nmap command suggestions
def hidden_script():

# Hidden_script function with a list of suggested Nmap commands
    print()
    print(f"{White}More suggested Nmap commands...{Reset}")
    
# Discovering Systems
    print(f"{Cyan}[*] Discovering Systems:{Reset}")
    print(f"%-24s %s" % ("-PS", "TCP SYN Ping"))
    print(f"%-24s %s" % ("-PA", "Ping TCP ACK"))
    print(f"%-24s %s" % ("-PU", "Ping UDP"))
    print(f"%-24s %s" % ("-PM", "Netmask Request"))
    print(f"%-24s %s" % ("-PP", "Timestamp Request"))
    print(f"%-24s %s" % ("-PE", "Echo Request"))
    print(f"%-24s %s" % ("-sL", "List Scan"))
    print(f"%-24s %s" % ("-PO", "Ping by Protocol"))
    print(f"%-24s %s" % ("-PN", "No Ping"))
    print(f"%-24s %s" % ("-n", "No DNS"))
    print(f"%-24s %s" % ("-R", "Resolve DNS for all target systems"))
    print(f"%-24s %s" % ("--traceroute", "Trace route to system (for network topologies)"))
    print(f"%-24s %s\n" % ("-sP", "Ping Scan, same as -PP -PM -PS443 -PA80"))

# Port Scanning Techniques
    print(f"{Cyan}[*] Port Scanning Techniques:{Reset}")
    print(f"%-24s %s" % ("-sS", "TCP SYN Scan"))
    print(f"%-24s %s" % ("-sT", "TCP Connect Scan"))
    print(f"%-24s %s" % ("-sU", "UDP Scan"))
    print(f"%-24s %s" % ("-sY", "SCTP INIT Scan"))
    print(f"%-24s %s" % ("-sZ", "SCTP COOKIE ECHO Scan"))
    print(f"%-24s %s" % ("-sO", "IP Protocol Scan"))
    print(f"%-24s %s" % ("-sW", "TCP Window Scan"))
    print(f"%-24s %s" % ("-sF", "NULL, FIN, XMAS Scans"))
    print(f"%-24s %s\n" % ("-sA", "TCP ACK Scan"))

# Ports to Scan and Scan Order
    print(f"{Cyan}[*] Ports to Scan and Scan Order:{Reset}")
    print(f"%-24s %s" % ("-p", "Port range"))
    print(f"%-24s %s" % ("-p-", "All ports"))
    print(f"%-24s %s" % ("-p n,m,z", "Specified ports"))
    print(f"%-24s %s" % ("-p U:n-m,z T:n,m", "U for UDP, T for TCP"))
    print(f"%-24s %s" % ("-F", "Fast mode - Scan 100 common ports"))
    print(f"%-24s %s" % ("--top-ports", "Scan the n most common ports"))
    print(f"%-24s %s\n" % ("-r", "Do not randomize"))

# Timing and Performance
    print(f"{Cyan}[*] Timing and Performance:{Reset}")
    print(f"%-24s %s" % ("-T0", "Paranoid"))
    print(f"%-24s %s" % ("-T1", "Sneaky"))
    print(f"%-24s %s" % ("-T2", "Polite"))
    print(f"%-24s %s" % ("-T3", "Normal"))
    print(f"%-24s %s" % ("-T4", "Aggressive"))
    print(f"%-24s %s" % ("-T5", "Insane"))
    print(f"%-24s %s" % ("--min-hostgroup", "Minimum host group"))
    print(f"%-24s %s" % ("--max-hostgroup", "Maximum host group"))
    print(f"%-24s %s" % ("--min-rate", "Minimum rate"))
    print(f"%-24s %s" % ("--max-rate", "Maximum rate"))
    print(f"%-24s %s" % ("--min-parallelism", "Minimum parallelism"))
    print(f"%-24s %s" % ("--max-parallelism", "Maximum parallelism"))
    print(f"%-24s %s" % ("--min-rtt-timeout", "Minimum RTT timeout"))
    print(f"%-24s %s" % ("--max-rtt-timeout", "Maximum RTT timeout"))
    print(f"%-24s %s" % ("--initial-rtt-timeout", "Initial RTT timeout"))
    print(f"%-24s %s" % ("--max-retries", "Maximum retries"))
    print(f"%-24s %s" % ("--host-timeout", "Host timeout"))
    print(f"%-24s %s\n" % ("--scan-delay", "Scan delay"))

# Service and Version Detection
    print(f"{Cyan}[*] Service and Version Detection:{Reset}")
    print(f"%-24s %s" % ("-sV", "Version detection of services"))
    print(f"%-24s %s" % ("--all-ports", "Do not exclude any ports"))
    print(f"%-24s %s" % ("--version-all", "Try all probes"))
    print(f"%-24s %s" % ("--version-trace", "Trace activity of version scan"))
    print(f"%-24s %s" % ("-O", "Enable OS detection"))
    print(f"%-24s %s" % ("--fuzzy", "Guess OS detection"))
    print(f"%-24s %s\n" % ("--max-os-tries", "Set maximum number of tries against target"))

# Firewall/IDS Evasion
    print(f"{Cyan}[*] Firewall/IDS Evasion:{Reset}")
    print(f"%-24s %s" % ("-f", "Fragment packets"))
    print(f"%-24s %s" % ("-D d1,d2", "Cloak scans with decoys"))
    print(f"%-24s %s" % ("-S ip", "Spoof source address"))
    print(f"%-24s %s" % ("--g source", "Spoof source port"))
    print(f"%-24s %s" % ("--randomize-hosts", "Randomize hosts order"))
    print(f"%-24s %s\n" % ("--spoof-mac", "Change source MAC address"))

# Detail and Debugging Parameters
    print(f"{Cyan}[*] Detail and Debugging Parameters:{Reset}")
    print(f"%-24s %s" % ("-v", "Increase verbosity level"))
    print(f"%-24s %s" % ("--reason", "Output the reason a port is marked as open, closed, or filteRed"))
    print(f"%-24s %s" % ("-d (1-9)", "Set the debugging level"))
    print(f"%-24s %s\n" % ("--packet-trace", "Trace packets"))

# Other Options
    print(f"{Cyan}[*] Other Options:{Reset}")
    print(f"%-24s %s" % ("--resume file", "Resume an aborted scan (using output formats from -oN or -oG)"))
    print(f"%-24s %s" % ("-6", "Enable IPv6 scanning"))
    print(f"%-24s %s\n" % ("-A", "Aggressive scan - Same as -O -sV -sC --traceroute"))

# Interactive Options
    print(f"{Cyan}[*] Interactive Options:{Reset}")
    print(f"%-24s %s" % ("v/V", "Increase/Decrease verbosity level"))
    print(f"%-24s %s" % ("d/D", "Increase/Decrease debugging level"))
    print(f"%-24s %s\n" % ("p/P", "Enable/Disable packet tracing"))

# Scripts
    print(f"{Cyan}[*] Scripts:{Reset}")
    print(f"%-24s %s" % ("-sC", "Scan with default scripts"))
    print(f"%-24s %s" % ("--script file", "Execute script (or all)"))
    print(f"%-24s %s" % ("--script-args n=v", "Provide script arguments"))
    print(f"%-24s %s\n" % ("--script-trace", "Show incoming and outgoing communication"))
    print(f"{Cyan}For more options, please visit the nmap documentation at https://nmap.org/docs.html{Reset}")  

# Checking for "help" command
# Check if the user has requested help, and if so, execute the hidden_script function
if len(sys.argv) > 1 and sys.argv[1].lower() == "help":
    hidden_script()
    sys.exit(0)

# Setting the history functionality
# Check if the inputrc file exists, if not, configure it for better command history navigation
inputrc_path = os.path.expanduser("~/.inputrc")
if not os.path.isfile(inputrc_path):
    with open(inputrc_path, "a") as inputrc:
        inputrc.write('"\e[A": history-search-backward\n')
        inputrc.write('"\e[B": history-search-forward\n')

# Banner
# Display the script banner with relevant information and instructions
print(f"{Cyan}\n-... -.--    .--. .-- -.. .-- --- .-. -.- ... - .- - .. --- -.{Reset}")
print(f"{Cyan}Using {Reset}{White}'python3 nmap-scan.py help' {Reset}{Cyan}or{Reset}{White} './nmap-scan.py help'{Cyan} command displays nmap command suggestion{Reset}")
print(f"{Cyan}Type {Reset}{White}'help'{Reset}{Cyan} when prompted to 'Enter additional options for nmap (separate multiple options by commas):'{Reset}")
print(f"{Cyan}At the end of the analysis, you will have the option to save the report in various formats{Reset}")
print(f"{Cyan}Note: The default target is {White}'localhost'{Reset}{Cyan} (127.0.0.1){Reset}")

# Define necessary variables for the script
current_dir = os.getcwd()
directory_name = "Report"
host_to_scan = "localhost"
original_host_to_scan = "localhost"
nmap_output = ""
stop_event = threading.Event()
loading_thread = threading.Thread()
extra_options_array = []  

# Function to validate IP addresses
def is_valid_ip(ip):
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            if not 0 <= int(part) <= 255:
                return False
        return True
    except (ValueError, AttributeError):
        return False

# Function to validate domain names
def is_valid_domain(host):
    if validators.domain(host):
        try:
            socket.gethostbyname(host)
            return True
        except socket.gaierror:
            return False
    else:
        return False

# Show the command being executed
# Display the default nmap command that will be executed
while True:
    print(f"{Reset}")
    response = input(f"[*] Please enter the target IP address/domain or range (e.g., 192.168.10.0/24) or press Enter to skip: ")

    # Validate the response
    if response.strip():  # If the response is not empty
        is_domain = is_valid_domain(response)
        is_ip = is_valid_ip(response)

        if is_ip and not is_domain:
            print(f"{Cyan}Valid IP!{Reset}")
            print(f"{Cyan}Command executed: {Reset}{White}nmap {response}{Reset}")
            host_to_scan = response  # Update the host_to_scan variable with the user input
            break
        elif is_domain and not is_ip:
            print(f"{Cyan}Valid Domain!{Reset}")
            print(f"{Cyan}Command executed: {Reset}{White}nmap {response}{Reset}")
            host_to_scan = response  # Update the host_to_scan variable with the user input
            break
        elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', response):
            print(f"{Cyan}Valid IP range!{Reset}")
            print(f"{Cyan}Command executed: {Reset}{White}nmap {response}{Reset}")
            host_to_scan = response  # Update the host_to_scan variable with the user input
            break
        else:
            print(f"{Red}[!] Invalid input!{Reset}")
    else:
        host_to_scan = "localhost"
        break

# Displaying nmap suggestions
previous_options = ""
while True:
    print(f"{Reset}")
    extra_options_response = input(f"[*] Would you like to include nmap additional options? (y/n) or Press Enter to confirm: ")
    if extra_options_response.lower() in ('y', ''):
        print(f"{Cyan}Here are some suggested nmap options:{Reset}")
        print(f"{Yellow}-sV --script vulners{Reset}        : Vulnerability Analysis")
        print(f"{Yellow}-sN{Reset}                         : Network Analysis")
        print(f"{Yellow}-p 1-1000{Reset}                   : Port Analysis")
        print(f"{Yellow}-O{Reset}                          : Operating System Analysis")
        print(f"{Yellow}-sV{Reset}                         : Service Version Analysis")
        print(f"{Yellow}-f -D RND:10{Reset}                : Firewall and IDS Evasion Analysis")
        print(f"{Yellow}--traceroute{Reset}                : Network Topology Analysis")
        print(f"{Yellow}--script <script>{Reset}           : Custom Script Analysis")
        print(f"{Yellow}-T4 -F{Reset}                      : Performance and Timing Analysis")
        print(f"{Yellow}--script-security <level>{Reset}   : Security Script Analysis")
        print(f"{Yellow}--packet-trace{Reset}              : Network Traffic Logging Analysis")
        print(f"{Yellow}--script ssl-enum-ciphers{Reset}   : SSL/TLS Encryption Analysis")
        print(f"{Yellow}--script rpcinfo{Reset}            : Remote Procedure Call (RPC) Service Analysis")
        print(f"{Yellow}--script smb-enum-shares{Reset}    : Server Message Block (SMB) Protocol Analysis")
        print(f"{Yellow}--script http-vuln-<script>{Reset} : Web Application Vulnerability Analysis")
        print(f"{Yellow}-sC{Reset}                         : Script Scan - Execute default scripts")
        print(f"{Yellow}-A{Reset}                          : Aggressive Scan - Enables OS and version detection, script scanning, and traceroute")
        print(f"{Yellow}-sS{Reset}                         : TCP SYN Scan - Stealthy scan for general scanning")
        print(f"{Yellow}-sT{Reset}                         : TCP Connect Scan - Completes the TCP three-way handshake")
        print(f"{Yellow}-sU{Reset}                         : UDP Scan - Scans for open UDP ports")
        print(f"{Cyan}For more options, please visit the nmap documentation at https://nmap.org/docs.html{Reset}")
        print(f"{Cyan}If you need more suggestions, please type {Reset}{White}'help'{Reset}")
        while True:
            print()
            if previous_options:
                print(f"Previous options: {previous_options}")
            extra_options = input(f"Enter extra nmap options, separated by commas (optional): ")

            if extra_options.lower() == "help":
                hidden_script()
                continue
                
            # Remove extra spaces and split the options
            extra_options_list = [opt.strip() for opt in extra_options.split(',')]  
               
            # Show the updated command with options before the domain or IP
            print(f"{Cyan}Scanning ports in {host_to_scan} with the following command: {Reset}{White}nmap {' '.join(extra_options_list)} {host_to_scan}{Reset}")
            # Update the definition of extra_options_array
            extra_options_array = extra_options.split(',')
            
            nmap_command = f"nmap {' '.join(extra_options_array)} {host_to_scan}"
            confirm = input(f"[*] Is the information correct? (y/n) or Press Enter to confirm: ")
            if confirm.lower() in ('y', ''):
                break
            elif confirm.lower() == 'n':
                print(f"Please make the necessary modifications.")
                continue
            else:
                print(f"{Red}[-] Invalid input. Please try again.{Reset}")
                continue
        break
    elif extra_options_response.lower() == 'n':
        nmap_command = f"nmap {host_to_scan}"  # Define nmap_command in case no additional options are added
        break
    else:
        print(f"{Red}[-] Invalid input. Please try again.{Reset}")

# Function to handle keyboard interrupts
def ctrl_c(signal, frame):
    sys.stdout.write(f"{Red}\r[!] Interrupt detected. Exiting the script...\n{Reset}")
    stop_event.set()
    os._exit(1)

# Function to display a loading effect until the scanning process begins
def loading_effect(stop_event):
    """
    Display a loading effect until the scanning process begins.
    Args:
    stop_event (threading.Event): Event to signal the stop of the loading effect.
    """
    start_time = time.time()
    print(f"{Yellow}")
    while not stop_event.is_set():
        for char in "|/-\\":
            elapsed_time = time.time() - start_time
            minutes, seconds = divmod(elapsed_time, 60)
            hours, minutes = divmod(minutes, 60)
            time_string = f"{int(hours):02d}:{int(minutes):02d}:{seconds:06.3f}"
            sys.stdout.write(f'\rLoading... {char} Elapsed Time: {time_string}')
            sys.stdout.flush()
            time.sleep(0.1)

# Set up the keyboard interrupt handler
def ctrl_c(signal, frame):
    print("\nCtrl+C captured, exiting...")
    stop_event.set()
    sys.exit(0)

# Start the loading effect in a separate thread
stop_event = threading.Event()
loading_thread = threading.Thread(target=loading_effect, args=(stop_event,))
loading_thread.start()

# Get nmap_output
if 'nmap_command' in locals():
    try:
        if host_to_scan != "localhost":
            nmap_command = f"nmap {' '.join(extra_options_array)} {host_to_scan}"
        nmap_output = subprocess.run(nmap_command.split(), capture_output=True, text=True).stdout
    except KeyboardInterrupt:
        stop_event.set()
        loading_thread.join()
        os._exit(1)

# Stop the loading effect
stop_event.set()
loading_thread.join()
print()

# Loop through the nmap output to highlight lines with specific content
for line in nmap_output.splitlines():
    if "open" in line:
        highlighted_line = f"{Yellow}[*] {line}{Reset}"
        print(f"{Yellow}{highlighted_line}{Reset}")
    elif f"{Cyan}Nmap scan report for{Reset}" in line or "filteRed" in line:
        print(line)
    else:
        print(f"{Reset}{line}{Reset}")

# Define the function to handle SIGINT
def handler(signum, frame):
    print()  # Add a line break before printing the interrupt message
    print(f"{Red}[!] Interrupt detected. Exiting the script...{Reset}")
    stop_event.set()
    loading_thread.join()
    os._exit(1)  # This will force the script to exit without executing any additional cleanup operations that might be on the stack.

# Set up the keyboard interrupt handler
signal.signal(signal.SIGINT, handler)

# Function to handle user input for saving the report in different formats
def handle_report_saving(nmap_output, current_dir, directory_name):
    while True:
        save_report = input(f"[*] Do you want to save the report? (y/n) or Press Enter to confirm: ")
        if save_report.lower() in ('y', ''):
            os.makedirs(f"{current_dir}/{directory_name}", exist_ok=True)
            print(f"{Cyan}[+] Created directory: {current_dir}/{directory_name}{Reset}")
            print(f"{Cyan}Available formats:{Reset}")
            print(f"{Cyan}-oN{Reset}    : Normal format")
            print(f"{Cyan}-oX{Reset}    : XML format")
            print(f"{Cyan}-oA{Reset}    : All formats")
            print(f"{Cyan}-oG{Reset}    : Grepable format")
            while True:
                save_format = input("[*] Choose the report format '-oN, -oX, -oA, -oG, or ALL' separated by commas (optional): ")
                save_formats_array = [item.strip() for item in save_format.replace(',', ' ').split()]
                valid_formats = []
                invalid_formats = []
                for format in save_formats_array:
                    if format.startswith("-") and format in ["-oN", "-oX", "-oA", "-oG"]:
                        valid_formats.append(format)
                    elif format.lower() == "all":
                        valid_formats.append(format)
                    else:
                        invalid_formats.append(format)

                if invalid_formats:
                    for invalid_format in invalid_formats:
                        print(f"{Red}[-] Invalid format option: {invalid_format}{Reset}")
                    continue
                else:
                    for valid_format in valid_formats:
                        if valid_format.lower() == "all":
                            for all_format in ["-oN", "-oX", "-oA", "-oG"]:
                                with open(f"{current_dir}/{directory_name}/port_scan_results{all_format}", "w") as file:
                                    file.write(nmap_output)
                                print(f"{Cyan}[+] Saved report in {all_format} format...{Reset}")
                        else:
                            with open(f"{current_dir}/{directory_name}/report_scannedPorts_{valid_format}", "w") as file:
                                file.write(nmap_output)
                            print(f"{Cyan}[+] Saved report in {valid_format} format...{Reset}")
                    print(f"{Yellow}{Reverse}Done")
                    break
            break

        elif save_report.lower() == "n":
            print(f"{Yellow}{Reverse}[-] Report not saved.")
            break

        else:
            print(f"{Red}[-] Invalid input. Please try again.{Reset}")

# Call the function to handle saving of the report in different formats
handle_report_saving(nmap_output, current_dir, directory_name)

# End of the script
