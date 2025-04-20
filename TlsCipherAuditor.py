# Auther: Michael Azoulay
# Usecase: check for specific ciphers in nmap output
# Dependencis: nmap installed in path. (can be called by typing nmap in terminal)
# Date: 20.04.2025
# Version: 0.2

import os
import re
import sys

# Add ANSI color codes
GREEN = '\033[92m'  # Green for safe ciphers
RED = '\033[91m'    # Red for unsafe ciphers
RESET = '\033[0m'   # Reset color

def show_help():
    help_text = f"""
{GREEN}TLS Cipher Auditor{RESET}
    
Usage:
    python TlsCipherAuditor.py [options] [domain]

Options:
    -h, --help      Show this help message
    
Arguments:
    domain          Domain name or IP address to check (optional)
                    If not provided, script will run in interactive mode

Interactive Mode Commands:
    quit, exit      Exit the program
    help            Show this help message

Examples:
    python TlsCipherAuditor.py example.com
    python TlsCipherAuditor.py --help
    python TlsCipherAuditor.py
        (enters interactive mode)
    """
    print(help_text)

def check_ciphers(domain):
    print("\nDomain: ", domain)
    cmd = f'nmap --script=ssl-enum-ciphers {domain}'

    # List of ciphers considered safe
    safe_ciphers = {
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"}

    # Dictionary to store ciphers grouped by SSL/TLS version
    ciphers_by_version = {}

    # Run nmap command and collect output
    output = os.popen(cmd).readlines()

    current_tls_version = None  # Track the SSL/TLS version
    total_safe_ciphers = 0  # Track total safe ciphers

    # Process the output to extract ciphers and their corresponding SSL/TLS version
    for line in output:
        line = line.strip()

        # Detect SSL/TLS version (e.g., "TLSv1.2:")
        version_match = re.match(r"^\|\s+(TLSv\d+\.\d+|TLSv\d+|SSLv\d+):", line)
        if version_match:
            if '1.0' or '1.1' not in version_match:
                current_tls_version = version_match.group(1)
                if current_tls_version not in ciphers_by_version:
                    ciphers_by_version[current_tls_version] = []
                continue  # Move to next line

        # Extract cipher names (e.g., "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA")
        cipher_match = re.search(r"TLS_[A-Z0-9_]+", line)
        if cipher_match and current_tls_version:
            cipher_name = cipher_match.group(0)
            ciphers_by_version[current_tls_version].append(cipher_name)

    # Print results
    for version, ciphers in ciphers_by_version.items():
        print(f"\n{version} Ciphers:")
        safe_to_use = [cipher for cipher in ciphers if cipher in safe_ciphers]
        not_safe_to_use = [cipher for cipher in ciphers if cipher not in safe_ciphers]

        print("  Safe to use ciphers:")
        for cipher in safe_to_use:
            print(f"    - {GREEN}{cipher}{RESET}")

        print("  Not safe to use ciphers:")
        for cipher in not_safe_to_use:
            print(f"    - {RED}{cipher}{RESET}")

        # Update total safe ciphers count
        total_safe_ciphers += len(safe_to_use)

    # Print total count of safe ciphers
    print(f"\nTotal safe to use ciphers: {GREEN}{total_safe_ciphers}{RESET}")

def main():
    try:
        if len(sys.argv) > 1:
            if sys.argv[1] in ['-h', '--help', 'help']:
                show_help()
                return
            check_ciphers(sys.argv[1])
        else:
            print("Enter 'quit' or 'exit' to stop the program, 'help' for usage information")
            while True:
                domain = input('\nDomain or IP: ')
                if domain.lower() in ['quit', 'exit']:
                    print("Exiting program...")
                    break
                elif domain.lower() in ['help', '-h', '--help']:
                    show_help()
                    continue
                if domain:
                    check_ciphers(domain)

    except KeyboardInterrupt:
        print("\nProgram terminated by user")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()