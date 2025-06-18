# Author: Michael Azoulay (https://www.linkedin.com/in/michael-azoulay/)
# Usecase: check for specific ciphers in nmap output
# Dependencies: nmap installed and 'requests' module for --update
# Date: 18.06.2025
# Version: 0.5 updated logic

import os
import re
import sys

try:
    import requests
except ImportError:
    requests = None

# ANSI color codes
GREEN = '\033[92m'  # Green for safe ciphers
RED = '\033[91m'  # Red for unsafe ciphers
RESET = '\033[0m'  # Reset color

CIPHER_FILE = "recommended_ciphers.txt"

# Default safe cipher list fallback
default_safe_ciphers = {
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
}


def show_help():
    help_text = f"""
{GREEN}TLS Cipher Auditor{RESET}

Usage:
    python TlsCipherAuditor.py [options] [domain]

Options:
    -h, --help      Show this help message
    --update        Update cipher list from IANA website

Arguments:
    $domain          Domain name or IP address to check (optional)
                    If not provided, script will run in interactive mode

Interactive Mode Commands:
    quit, exit      Exit the program
    help            Show this help message

Examples:
    python TlsCipherAuditor.py example.com
    python TlsCipherAuditor.py --update
    python TlsCipherAuditor.py
        (enters interactive mode)
"""
    print(help_text)


def normalize_cipher_name(cipher_name):
    # Normalize TLS 1.3 style ciphers like TLS_AKE_WITH_AES_128_GCM_SHA256 -> TLS_AES_128_GCM_SHA256
    if cipher_name.startswith("TLS_AKE_WITH_"):
        cipher_name = cipher_name.replace("TLS_AKE_WITH_", "TLS_")
    return cipher_name


def update_cipher_list():
    if not requests:
        print(f"{RED}[-] 'requests' module not installed. Cannot update cipher list.{RESET}")
        return False
    try:
        print("Fetching recommended ciphers from IANA...")
        url = "https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4"
        html = requests.get(url).text
        table = html.split('name="tls-parameters-4"')[1].split("</table>")[0]
        rows = re.findall(r"<tr>(.*?)</tr>", table, re.DOTALL)[1:]
        ciphers = {
            re.findall(r"<td.*?>(.*?)</td>", row)[1].strip()
            for row in rows if 'Y' in row.split("</td>")[3]
        }
        with open(CIPHER_FILE, "w") as f:
            for c in sorted(ciphers):
                f.write(c + "\n")
        print(f"{GREEN}[+] Updated and saved {len(ciphers)} ciphers to {CIPHER_FILE}.{RESET}")
        return True
    except Exception as e:
        print(f"{RED}[-] Failed to update cipher list: {e}{RESET}")
        return False


def load_cipher_list():
    try:
        with open(CIPHER_FILE, "r") as f:
            ciphers = {line.strip() for line in f if line.strip()}
        print(f"{GREEN}[+] Loaded {len(ciphers)} ciphers from {CIPHER_FILE}.{RESET}")
        return ciphers
    except FileNotFoundError:
        print(f"{RED}[-] {CIPHER_FILE} not found. Using default cipher list.{RESET}")
        return default_safe_ciphers


def check_ciphers(domain):
    print(f"\nDomain: {domain}")
    cmd = f'nmap --script=ssl-enum-ciphers {domain}'

    safe_ciphers = load_cipher_list()

    # Dictionary to store ciphers grouped by SSL/TLS version
    ciphers_by_version = {}

    output = os.popen(cmd).readlines()

    current_tls_version = None
    total_safe_ciphers = 0

    for line in output:
        line = line.strip()

        version_match = re.match(r"^\|\s+(TLSv\d+\.\d+|TLSv\d+|SSLv\d+):", line)
        if version_match:
            current_tls_version = version_match.group(1)
            if current_tls_version not in ciphers_by_version:
                ciphers_by_version[current_tls_version] = []
            continue

        cipher_match = re.search(r"TLS_[A-Z0-9_]+", line)
        if cipher_match and current_tls_version:
            raw_cipher = cipher_match.group(0)
            cipher_name = normalize_cipher_name(raw_cipher)
            ciphers_by_version[current_tls_version].append(cipher_name)

    for version, ciphers in ciphers_by_version.items():
        print(f"\n{version} Ciphers:")
        safe = [c for c in ciphers if c in safe_ciphers]
        unsafe = [c for c in ciphers if c not in safe_ciphers]

        print("  Safe to use ciphers:")
        for c in safe:
            print(f"    - {GREEN}{c}{RESET}")

        print("  Not safe to use ciphers:")
        for c in unsafe:
            print(f"    - {RED}{c}{RESET}")

        total_safe_ciphers += len(safe)

    print(f"\nTotal safe ciphers found: {GREEN}{total_safe_ciphers}{RESET}")


def main():
    try:
        if len(sys.argv) > 1:
            arg = sys.argv[1].lower()
            if arg in ['-h', '--help', 'help']:
                show_help()
                return
            elif arg in ['-u', '--update', 'update']:
                success = update_cipher_list()
                sys.exit(0 if success else 1)
            else:
                check_ciphers(sys.argv[1])
        else:
            print("Enter 'quit' or 'exit' to stop the program, 'help' for usage information")
            while True:
                domain = input('\nDomain or IP: ').strip()
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