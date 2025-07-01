#!/usr/bin/env python3
# Security Breach by Sanskar Bhobaskar (Enhanced by Gemini)

import requests
import socket
import sys
import os
import datetime
import time

# Global buffer to store all printed results for logging
results_buffer = []

def print_and_log(message):
    """Prints a message to the console and appends it to the results buffer."""
    print(message)
    results_buffer.append(message)

def banner():
    """Displays the tool's banner and available options."""
    os.system("clear") # Clears the terminal screen
    print_and_log(r"""
 ____  ____  ____   ____  ____  ____   ____  ____  _  _
/ ___)/ ___)(_  _) / ___)(_  _)(_  _) / ___)(_  _)( \/ )
\___ \\___ \  )(   \___ \  )(    )(  \___ \  )(   \  /
(____/(____/ (__)  (____/ (__)  (__) (____/ (__)  (__)

    R3CON TOOL
    """)
    print_and_log("By Sanskar Bhobaskar") # This will appear below the ASCII art
    print_and_log("[1] HTTP Recon (HTTP Headers)")
    print_and_log("[2] Subdomain Enumeration (Common/Custom Wordlist)")
    print_and_log("[3] Directory Bruteforce (Common/Custom Wordlist)")
    print_and_log("[4] Port Scan (Single/Range/Common Ports)") # Updated description
    print_and_log("[5] Basic Banner Grabbing (Common Service Ports)")
    print_and_log("[6] Robots.txt Finder")
    print_and_log("[7] DNS Lookup (A, CNAME Records)")
    print_and_log("[8] Service Version Scan (Detailed Banner Grabbing)")
    print_and_log("[9] OS Inference (Basic via Banners/Headers)")
    print_and_log("[q] Quit")

def load_wordlist(filepath):
    """Loads a wordlist from a given file path."""
    try:
        with open(filepath, 'r') as f:
            # Strip whitespace and filter out empty lines
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print_and_log(f"[-] Error: Wordlist file '{filepath}' not found.")
        return None
    except Exception as e:
        print_and_log(f"[-] Error loading wordlist from '{filepath}': {e}")
        return None

def http_recon(target):
    """Gathers HTTP headers from the target web server."""
    print_and_log(f"\n[+] Gathering HTTP headers for http://{target}...\n")
    try:
        r = requests.get(f"http://{target}", timeout=5)
        print_and_log(f"    URL: {r.url}")
        print_and_log(f"    Status Code: {r.status_code}")
        print_and_log("    Headers:")
        for header, value in r.headers.items():
            print_and_log(f"        {header}: {value}")
    except requests.exceptions.ConnectionError:
        print_and_log(f"[-] Connection Error: Could not connect to http://{target}. Target might be down or unreachable.")
    except requests.exceptions.Timeout:
        print_and_log(f"[-] Timeout Error: Request to http://{target} timed out.")
    except Exception as e:
        print_and_log(f"[-] An unexpected error occurred during HTTP Recon: {e}")

def subdomain_enum(target):
    """Enumerates common subdomains for the target using a common list or custom wordlist."""
    print_and_log(f"\n[+] Starting subdomain enumeration for {target}...\n")
    
    # Default common subdomain list
    default_subdomains = ["www", "mail", "ftp", "test", "dev", "blog", "api", "shop", "admin",
                          "webmail", "ns1", "ns2", "vpn", "portal", "status", "docs", "jira",
                          "confluence", "git", "repo", "cdn"]
    
    wordlist_choice = input("Use custom wordlist for subdomains? (y/N): ").strip().lower()
    subdomains_to_check = []

    if wordlist_choice == 'y':
        filepath = input("Enter path to custom subdomain wordlist file: ").strip()
        custom_list = load_wordlist(filepath)
        if custom_list:
            subdomains_to_check = custom_list
            print_and_log(f"[+] Using custom wordlist with {len(subdomains_to_check)} entries.")
        else:
            print_and_log("[-] Custom wordlist not loaded. Falling back to default common subdomains.")
            subdomains_to_check = default_subdomains
    else:
        subdomains_to_check = default_subdomains
        print_and_log("[+] Using default common subdomains.")

    if not subdomains_to_check:
        print_and_log("[-] No subdomains to check. Exiting subdomain enumeration.")
        return

    found_subdomains = []
    for sub in subdomains_to_check:
        url = f"http://{sub}.{target}"
        try:
            r = requests.get(url, timeout=2)
            if r.status_code < 400 or r.status_code == 401 or r.status_code == 403:
                print_and_log(f"[+] Found: {url} (Status: {r.status_code})")
                found_subdomains.append(url)
        except requests.exceptions.ConnectionError:
            pass
        except requests.exceptions.Timeout:
            pass
        except Exception as e:
            print_and_log(f"[-] Error checking {url}: {e}")
    
    if not found_subdomains:
        print_and_log("[-] No subdomains found.")

def dir_bruteforce(target):
    """Bruteforces common directories on the target web server using a common list or custom wordlist."""
    print_and_log(f"\n[+] Starting directory bruteforce on http://{target}...\n")
    
    # Default common directory list
    default_dirs = ["admin", "login", "dashboard", "uploads", "backup", "test", "dev",
                    "config", "phpmyadmin", "robots.txt", ".git", ".env", "api", "assets",
                    "images", "css", "js", "includes", "data", "temp"]
    
    wordlist_choice = input("Use custom wordlist for directories? (y/N): ").strip().lower()
    dirs_to_check = []

    if wordlist_choice == 'y':
        filepath = input("Enter path to custom directory wordlist file: ").strip()
        custom_list = load_wordlist(filepath)
        if custom_list:
            dirs_to_check = custom_list
            print_and_log(f"[+] Using custom wordlist with {len(dirs_to_check)} entries.")
        else:
            print_and_log("[-] Custom wordlist not loaded. Falling back to default common directories.")
            dirs_to_check = default_dirs
    else:
        dirs_to_check = default_dirs
        print_and_log("[+] Using default common directories.")

    if not dirs_to_check:
        print_and_log("[-] No directories to check. Exiting directory bruteforce.")
        return

    found_dirs = []
    for d in dirs_to_check:
        url = f"http://{target}/{d}"
        try:
            r = requests.get(url, timeout=2)
            if r.status_code != 404:
                print_and_log(f"[+] Found: {url} (Status: {r.status_code})")
                found_dirs.append(url)
        except requests.exceptions.ConnectionError:
            pass
        except requests.exceptions.Timeout:
            pass
        except Exception as e:
            print_and_log(f"[-] Error checking {url}: {e}")
    
    if not found_dirs:
        print_and_log("[-] No directories found.")

def port_scan(target):
    """Scans ports on the target based on user choice (single, range, or common)."""
    print_and_log(f"\n[+] Starting port scan on {target}...\n")
    
    # A comprehensive list of common ports
    common_ports = [20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 135, 137, 138, 139,
                    143, 161, 162, 389, 443, 445, 500, 514, 548, 587, 636, 993, 995, 1080,
                    1723, 3306, 3389, 5900, 8080, 8443, 8000, 4444, 5000, 5432, 6379, 27017]
    
    ports_to_scan = []
    
    while True:
        scan_type = input("Select scan type: [S]ingle port, [R]ange of ports, [C]ommon ports (default): ").strip().lower()
        
        if scan_type == 's':
            try:
                port = int(input("Enter single port number (1-65535): ").strip())
                if 1 <= port <= 65535:
                    ports_to_scan = [port]
                    print_and_log(f"[+] Scanning single port: {port}")
                    break
                else:
                    print_and_log("[-] Invalid port number. Please enter a number between 1 and 65535.")
            except ValueError:
                print_and_log("[-] Invalid input. Please enter a numeric port number.")
        
        elif scan_type == 'r':
            try:
                start_port = int(input("Enter start port number (1-65535): ").strip())
                end_port = int(input("Enter end port number (1-65535): ").strip())
                
                if 1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port:
                    ports_to_scan = list(range(start_port, end_port + 1))
                    print_and_log(f"[+] Scanning port range: {start_port}-{end_port}")
                    break
                else:
                    print_and_log("[-] Invalid port range. Ensure ports are between 1 and 65535, and start port is not greater than end port.")
            except ValueError:
                print_and_log("[-] Invalid input. Please enter numeric port numbers.")
        
        elif scan_type == 'c' or scan_type == '': # Default to common ports
            ports_to_scan = common_ports
            print_and_log("[+] Scanning common ports.")
            break
        
        else:
            print_and_log("[-] Invalid scan type. Please choose 's', 'r', or 'c'.")

    if not ports_to_scan:
        print_and_log("[-] No ports selected for scanning. Exiting port scan.")
        return

    open_ports = []
    for port in ports_to_scan:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5) # Shorter timeout for faster scan
        try:
            result = s.connect_ex((target, port))
            if result == 0:
                print_and_log(f"[+] Port {port} open")
                open_ports.append(port)
        except socket.gaierror:
            print_and_log(f"[-] Hostname could not be resolved: {target}")
            return
        except socket.error as e:
            print_and_log(f"[-] Socket error during port scan on port {port}: {e}")
        finally:
            s.close()
    
    if not open_ports:
        print_and_log("[-] No ports found open in the selected range/list.")
    return open_ports

def banner_grab(target):
    """Performs basic banner grabbing on a predefined set of common service ports."""
    print_and_log(f"\n[+] Grabbing basic banners from common service ports on {target}...\n")
    ports = [21, 22, 25, 80, 110, 143, 443] # Common ports for basic banner grab
    found_banners = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1) # Shorter timeout
        try:
            s.connect((target, port))
            # For HTTP/HTTPS, send a basic GET request to provoke a response
            if port == 80 or port == 443:
                s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            
            banner = s.recv(4096).decode(errors='ignore').strip()
            if banner:
                print_and_log(f"[+] Port {port} banner:")
                for line in banner.split('\n')[:3]: # Show first 3 lines of banner
                    print_and_log(f"    {line}")
                found_banners.append(f"Port {port}: {banner.splitlines()[0]}")
            else:
                print_and_log(f"[-] No banner received for port {port}.")
        except (socket.timeout, ConnectionRefusedError):
            print_and_log(f"[-] Port {port} is closed or filtered (timeout/refused).")
        except Exception as e:
            print_and_log(f"[-] Error grabbing banner on port {port}: {e}")
        finally:
            s.close()
    if not found_banners:
        print_and_log("[-] No banners found on common ports.")

def robots_finder(target):
    """Checks for and displays the content of robots.txt on the target."""
    print_and_log(f"\n[+] Checking for robots.txt on http://{target}/robots.txt...\n")
    try:
        r = requests.get(f"http://{target}/robots.txt", timeout=3)
        if r.status_code == 200:
            print_and_log(f"[+] robots.txt found:")
            print_and_log(r.text)
        else:
            print_and_log(f"[-] robots.txt not found (Status: {r.status_code})")
    except requests.exceptions.ConnectionError:
        print_and_log(f"[-] Connection Error: Could not connect to http://{target}. Target might be down or unreachable.")
    except requests.exceptions.Timeout:
        print_and_log(f"[-] Timeout Error: Request to http://{target}/robots.txt timed out.")
    except Exception as e:
        print_and_log(f"[-] An unexpected error occurred during robots.txt check: {e}")

def dns_lookup(target):
    """Performs basic DNS A and CNAME record lookups."""
    print_and_log(f"\n[+] Performing DNS lookups for {target}...\n")
    try:
        # A records (IP Addresses)
        ip_addresses = socket.gethostbyname_ex(target)[2]
        print_and_log(f"    A Records (IP Addresses): {', '.join(ip_addresses)}")

        # CNAME records (Aliases)
        aliases = socket.gethostbyname_ex(target)[1]
        if aliases:
            print_and_log(f"    CNAME Records (Aliases): {', '.join(aliases)}")
        else:
            print_and_log("    No CNAME records found via simple lookup.")

        print_and_log("\n    Note: MX, NS, and TXT records require more advanced DNS querying (e.g., using a dedicated DNS library like 'dnspython') which is beyond simple socket operations. Consider using 'dig' or 'nslookup' for more comprehensive DNS information.")

    except socket.gaierror:
        print_and_log(f"[-] Hostname could not be resolved for DNS lookup: {target}")
    except Exception as e:
        print_and_log(f"[-] An unexpected error occurred during DNS lookup: {e}")

def service_version_scan(target):
    """Attempts to identify service versions by analyzing banners on common ports."""
    print_and_log(f"\n[+] Attempting service version detection on common ports for {target}...\n")
    # Common ports for version detection and their expected service types
    ports_to_check = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 80: "HTTP",
        110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP",
        5900: "VNC", 8080: "HTTP-Proxy"
    }
    
    found_services = []

    for port, service_name in ports_to_check.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5) # Slightly longer timeout for version scan
        try:
            s.connect((target, port))
            print_and_log(f"[+] Port {port} ({service_name}) is open. Attempting banner grab...")
            
            # Send specific probes for common services to elicit more detailed banners
            if port == 80: # HTTP
                s.sendall(f"HEAD / HTTP/1.0\r\nHost: {target}\r\nUser-Agent: SecurityBreach/1.0\r\n\r\n".encode())
            elif port == 443: # HTTPS - Raw socket HTTPS is complex, this will likely fail or get garbled.
                # True HTTPS banner grabbing needs SSL/TLS libraries.
                print_and_log("    Note: HTTPS banner grabbing via raw sockets is limited without SSL/TLS libraries.")
                s.sendall(f"GET / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode())
            elif port == 21: # FTP
                # FTP often sends banner immediately upon connection
                pass
            elif port == 22: # SSH
                # SSH sends banner immediately upon connection
                pass
            elif port == 25: # SMTP
                # SMTP sends banner immediately upon connection
                pass
            else:
                s.sendall(b"\r\n") # Generic probe for other services

            banner = s.recv(4096).decode(errors='ignore').strip()
            if banner:
                print_and_log(f"    Banner for {service_name} on {port}:")
                for line in banner.split('\n')[:5]: # Show first 5 lines of banner
                    print_and_log(f"        {line}")
                found_services.append(f"{service_name} ({port}): {banner.splitlines()[0]}")
            else:
                print_and_log(f"    No banner received for {service_name} on {port}.")

        except socket.timeout:
            print_and_log(f"[-] Port {port} ({service_name}) is closed or filtered (timeout).")
        except ConnectionRefusedError:
            print_and_log(f"[-] Port {port} ({service_name}) is closed (connection refused).")
        except Exception as e:
            print_and_log(f"[-] Error during service version scan for {service_name} on port {port}: {e}")
        finally:
            s.close()
    if not found_services:
        print_and_log("[-] No services found with identifiable banners on common ports.")

def os_inference(target):
    """Attempts a very basic OS inference based on HTTP headers and service banners."""
    print_and_log(f"\n[+] Attempting very basic OS inference for {target}...\n")
    print_and_log("    Note: OS detection without advanced fingerprinting (like Nmap) is highly unreliable.")
    print_and_log("    Inference below is based on common service banners and HTTP headers only, and can be inaccurate or spoofed.")

    # Try HTTP Server header for OS inference
    try:
        r = requests.get(f"http://{target}", timeout=5)
        if 'Server' in r.headers:
            server_header = r.headers['Server'].lower()
            print_and_log(f"    HTTP Server header: {r.headers['Server']}")
            if "iis" in server_header:
                print_and_log("    Inference: Likely Windows (IIS web server)")
            elif "apache" in server_header or "nginx" in server_header:
                print_and_log("    Inference: Likely Linux/Unix (Apache or Nginx web server)")
            elif "gws" in server_header:
                print_and_log("    Inference: Google Web Server (often Linux-based)")
            else:
                print_and_log("    Inference: Cannot determine OS from HTTP Server header alone.")
        else:
            print_and_log("    No 'Server' header found in HTTP response.")
    except requests.exceptions.ConnectionError:
        print_and_log(f"[-] Could not connect to http://{target} for HTTP OS inference.")
    except requests.exceptions.Timeout:
        print_and_log(f"[-] Timeout during HTTP OS inference attempt.")
    except Exception as e:
        print_and_log(f"[-] Error during HTTP OS inference attempt: {e}")

    # Try SSH banner for OS inference (if port 22 is open)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((target, 22))
        ssh_banner = s.recv(1024).decode(errors='ignore').strip()
        s.close()
        if ssh_banner:
            print_and_log(f"    SSH Banner (Port 22): {ssh_banner.splitlines()[0]}")
            if "openssh" in ssh_banner.lower():
                print_and_log("    Inference: Likely Linux/Unix (OpenSSH)")
            elif "ssh-2.0-libssh" in ssh_banner.lower():
                print_and_log("    Inference: Could be Linux/Unix or other systems using libssh")
            else:
                print_and_log("    Inference: Cannot determine OS from SSH banner alone.")
        else:
            print_and_log("    No SSH banner received on port 22.")
    except (socket.timeout, ConnectionRefusedError):
        print_and_log("    Port 22 (SSH) not open or timed out, skipping SSH banner inference.")
    except Exception as e:
        print_and_log(f"[-] Error during SSH OS inference attempt: {e}")

def save_results_to_file(target):
    """Saves all logged results to a text file within a 'results' folder."""
    results_dir = "results"
    # Create the results directory if it doesn't exist
    os.makedirs(results_dir, exist_ok=True)

    current_time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"results_{target}_{current_time}.txt"
    filepath = os.path.join(results_dir, filename) # Join directory and filename

    try:
        with open(filepath, "w") as f:
            for line in results_buffer:
                f.write(line + "\n")
        print_and_log(f"\n[+] All recon results saved to {filepath}")
    except Exception as e:
        print_and_log(f"[-] Error saving results to file {filepath}: {e}")

def main():
    """Main function to run the Security Breach tool."""
    if len(sys.argv) != 2:
        print_and_log("Usage: python3 secbreach.py <target>")
        sys.exit(1) # Exit with an error code

    target = sys.argv[1]
    
    while True:
        banner() # Show banner and options
        choice = input("\nSelect Module (or 'q' to quit): ").strip().lower()

        if choice == "1":
            http_recon(target)
        elif choice == "2":
            subdomain_enum(target)
        elif choice == "3":
            dir_bruteforce(target)
        elif choice == "4":
            port_scan(target)
        elif choice == "5":
            banner_grab(target)
        elif choice == "6":
            robots_finder(target)
        elif choice == "7":
            dns_lookup(target)
        elif choice == "8":
            service_version_scan(target)
        elif choice == "9":
            os_inference(target)
        elif choice == "q":
            print_and_log("\nExiting Security Breach. Generating results file...")
            save_results_to_file(target)
            break # Exit the loop
        else:
            print_and_log("[-] Invalid option. Please select a valid number or 'q'.")
        
        # Pause for user to read results before clearing and showing menu again
        if choice != 'q': # Don't pause if quitting
            input("\nPress Enter to continue recon...")

if __name__ == "__main__":
    main()

