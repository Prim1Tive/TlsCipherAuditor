# Author: Michael Azoulay (https://www.linkedin.com/in/michael-azoulay/)
# Usecase: check for specific ciphers in nmap output
# Dependencies: nmap installed and 'requests' module for --update
# Date: 18.06.2025
# Version: 0.5 updated logic

import os
import re
import sys
import argparse
import subprocess
import shutil
import html

try:
    import requests
except ImportError:
    requests = None

# Runtime flags
QUIET = False
USE_COLOR = True

# ANSI color codes
GREEN = '\033[92m'  # Green for safe ciphers
RED = '\033[91m'  # Red for unsafe ciphers
RESET = '\033[0m'  # Reset color

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CIPHER_FILE = os.path.join(SCRIPT_DIR, "recommended_ciphers.txt")

# Default safe cipher list fallback
default_safe_ciphers = {
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_DHE_PSK_WITH_AES_128_CCM",
    "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_PSK_WITH_AES_256_CCM",
    "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_DHE_RSA_WITH_AES_128_CCM",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_CCM",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256",
    "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
}


def show_help():
    title = f"{GREEN}TLS Cipher Auditor{RESET}" if USE_COLOR else "TLS Cipher Auditor"
    help_text = (
        f"{title}\n\n"
        "Usage:\n"
        "    python TlsCipherAuditor.py [options] [domain]\n\n"
        "Options:\n"
        "    -h, --help            Show this help message\n"
        "    -u, --update          Update cipher list from IANA website\n"
        "    -q, --quiet           Suppress non-essential output\n"
        "        --quite          (Alias for --quiet)\n"
        "        --no-color       Disable ANSI colors\n\n"
        "Arguments:\n"
        "    domain                Domain name or IP address to check (optional)\n"
        "                          If not provided, script runs in interactive mode\n\n"
        "Interactive Mode Commands:\n"
        "    quit, exit            Exit the program\n"
        "    help                  Show this help message\n\n"
        "Examples:\n"
        "    python TlsCipherAuditor.py example.com\n"
        "    python TlsCipherAuditor.py --update\n"
        "    python TlsCipherAuditor.py\n"
        "        (enters interactive mode)\n"
    )
    print(help_text)


def normalize_cipher_name(cipher_name):
    # Normalize TLS 1.3 style ciphers like TLS_AKE_WITH_AES_128_GCM_SHA256 -> TLS_AES_128_GCM_SHA256
    if cipher_name.startswith("TLS_AKE_WITH_"):
        cipher_name = cipher_name.replace("TLS_AKE_WITH_", "TLS_")
    return cipher_name


def _strip_html(text):
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return html.unescape(text).strip()


def update_cipher_list():
    if not requests:
        print(f"{RED}[-] 'requests' module not installed. Cannot update cipher list.{RESET}" if not QUIET else "'requests' missing; cannot update.")
        return False
    try:
        if not QUIET:
            print("Fetching recommended ciphers from IANA...")
        url = "https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4"
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        page = resp.text

        # Limit parsing to the TLS Cipher Suites section only (tls-parameters-4)
        anchor = re.search(r"<(?:a|h\d)[^>]+(?:id|name)=\"tls-parameters-4\"", page, re.IGNORECASE)
        if not anchor:
            raise RuntimeError("TLS Cipher Suites section (tls-parameters-4) not found")
        start_idx = anchor.start()
        next_anchor = re.search(r"<(?:a|h\d)[^>]+(?:id|name)=\"tls-parameters-\d+\"", page[start_idx+1:], re.IGNORECASE)
        if next_anchor:
            end_idx = start_idx + 1 + next_anchor.start()
        else:
            end_idx = len(page)

        section = page[start_idx:end_idx]

        # Scan only tables in this section and pick those with expected headers
        tables = re.findall(r"<table[\s\S]*?>[\s\S]*?</table>", section, re.IGNORECASE)
        ciphers = set()
        matched_tables = 0

        for table_html in tables:
            # Collect header cells
            header_cells = re.findall(r"<th[^>]*>([\s\S]*?)</th>", table_html, re.IGNORECASE)
            if not header_cells:
                continue
            headers = [_strip_html(h).lower() for h in header_cells]

            # Determine indices
            idx_rec = None
            for i, h in enumerate(headers):
                if "recommended" in h or h.startswith("rec"):
                    idx_rec = i
                    break
            idx_name = None
            # Prefer 'description' which contains the cipher suite names
            for i, h in enumerate(headers):
                if "description" in h or "cipher" in h or "suite" in h:
                    idx_name = i
                    break
            # DTLS-OK column
            idx_dtls = None
            for i, h in enumerate(headers):
                if "dtls-ok" in h or h.replace(" ", "") == "dtlsok" or h.strip() == "dtls" or ("dtls" in h and "ok" in h):
                    idx_dtls = i
                    break

            if idx_rec is None or idx_name is None or idx_dtls is None:
                continue

            # Extract data rows
            data_rows = re.findall(r"<tr[\s\S]*?>([\s\S]*?)</tr>", table_html, re.IGNORECASE)
            data_rows = [r for r in data_rows if re.search(r"<td", r, re.IGNORECASE)]
            if not data_rows:
                continue

            matched_tables += 1
            for row in data_rows:
                cells = re.findall(r"<t[dh][^>]*>([\s\S]*?)</t[dh]>", row, re.IGNORECASE)
                if not cells:
                    continue
                if max(idx_rec, idx_name, idx_dtls) >= len(cells):
                    continue
                rec_text = _strip_html(cells[idx_rec]).strip().upper()
                name_text = _strip_html(cells[idx_name]).strip()
                dtls_text = _strip_html(cells[idx_dtls]).strip().upper()
                # Consider recommended only when both Recommended and DTLS-OK start with Y (Y, Yes, Y*)
                if name_text and rec_text.startswith('Y') and dtls_text.startswith('Y'):
                    ciphers.add(name_text)

        if not ciphers:
            raise RuntimeError("No ciphers parsed from IANA page")

        with open(CIPHER_FILE, "w", encoding="utf-8") as f:
            for c in sorted(ciphers):
                f.write(c + "\n")
        if not QUIET:
            print(f"{GREEN}[+] Parsed {len(ciphers)} ciphers with Recommended=Y and DTLS-OK=Y from {matched_tables} table(s). Saved to {CIPHER_FILE}.{RESET}")
        else:
            print(f"Updated {len(ciphers)} ciphers -> {CIPHER_FILE}")
        return True
    except Exception as e:
        print(f"{RED}[-] Failed to update cipher list: {e}{RESET}")
        return False


def load_cipher_list():
    try:
        with open(CIPHER_FILE, "r", encoding="utf-8") as f:
            ciphers = {line.strip() for line in f if line.strip()}
        if not QUIET:
            print(f"{GREEN}[+] Loaded {len(ciphers)} ciphers from {CIPHER_FILE}.{RESET}")
        return ciphers
    except FileNotFoundError:
        if not QUIET:
            print(f"{RED}[-] {CIPHER_FILE} not found. Using default cipher list. (Use -u/--update to create {CIPHER_FILE}){RESET}")
        return default_safe_ciphers


def check_ciphers(domain):
    print(f"\nDomain: {domain}")

    if shutil.which("nmap") is None:
        print(f"{RED}[-] 'nmap' executable not found in PATH. Please install nmap and try again.{RESET}")
        return

    safe_ciphers = load_cipher_list()

    ciphers_by_version = {}

    try:
        result = subprocess.run([
            "nmap",
            "--script=ssl-enum-ciphers",
            str(domain)
        ], capture_output=True, text=True, check=False)
    except Exception as e:
        print(f"{RED}[-] Failed to run nmap: {e}{RESET}")
        return

    if result.returncode != 0 and result.stderr:
        print(f"{RED}[-] nmap error: {result.stderr.strip()}{RESET}")

    lines = result.stdout.splitlines()

    current_tls_version = None
    total_safe_ciphers = 0

    for raw_line in lines:
        line = raw_line.strip()

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

    if not ciphers_by_version:
        print(f"{RED}[-] No cipher information parsed from nmap output.{RESET}")
        return

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
    global QUIET, USE_COLOR, GREEN, RED, RESET
    try:
        parser = argparse.ArgumentParser(add_help=True, description="Audit TLS cipher suites reported by nmap against a recommended list.")
        parser.add_argument("domain", nargs="?", help="Domain name or IP address to check")
        parser.add_argument("-u", "--update", action="store_true", help="Update cipher list from IANA website")
        parser.add_argument("-q", "--quiet", action="store_true", help="Suppress non-essential output")
        parser.add_argument("--quite", action="store_true", help=argparse.SUPPRESS)
        parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors in output")

        args = parser.parse_args()

        QUIET = bool(args.quiet or args.quite)
        USE_COLOR = sys.stdout.isatty() and not args.no_color

        if not USE_COLOR:
            GREEN = ""
            RED = ""
            RESET = ""

        if args.update:
            success = update_cipher_list()
            sys.exit(0 if success else 1)

        if args.domain:
            check_ciphers(args.domain)
            return

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
