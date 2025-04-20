# Cipher Check Script

A Python script that analyzes SSL/TLS ciphers using nmap's ssl-enum-ciphers script and provides a color-coded output of safe and unsafe ciphers.

## Description

This script automates the process of checking SSL/TLS ciphers on a target domain or IP address. It uses nmap's ssl-enum-ciphers script to enumerate supported ciphers and categorizes them as safe or unsafe based on modern security standards. The results are displayed with color coding for better visibility:
- 🟢 Safe ciphers are shown in green
- 🔴 Unsafe ciphers are shown in red

## Requirements

- Python 3.x
- nmap installed and accessible from PATH

## Installation

1. Ensure nmap is installed on your system:
   ```bash
   # For Ubuntu/Debian
   sudo apt-get install nmap

   # For CentOS/RHEL
   sudo yum install nmap

   # For macOS
   brew install nmap
   ```

2. Download the script:
   ```bash
   curl -O https://raw.githubusercontent.com/Prim1Tive/cipher-check/main/cipher-check.py
   or
   git clone 
   ```

3. Make the script executable:
   ```bash
   chmod +x cipher-check.py
   ```

## Usage

You can run the script in two ways:

1. With a command-line argument:
   ```bash
   python cipher-check.py example.com
   ```

2. Interactive mode:
   ```bash
   python cipher-check.py
   # You will be prompted to enter a domain or IP
   ```

## Safe Ciphers

The script considers the following ciphers as safe:
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- TLS_AES_128_GCM_SHA256
- TLS_AES_256_GCM_SHA384
- TLS_CHACHA20_POLY1305_SHA256
- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384

All other ciphers are marked as unsafe.

## Output Format

The script outputs:
1. SSL/TLS version information
2. List of safe ciphers (in green)
3. List of unsafe ciphers (in red)
4. Total count of safe ciphers found

## Example Output 