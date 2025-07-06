# TLS Cipher Auditor

A Python script that analyzes SSL/TLS ciphers using nmap's ssl-enum-ciphers script and provides a color-coded output of safe and unsafe ciphers. The script supports updating the safe cipher list from the official IANA TLS parameters registry.

## Disclaimer

**Important Notice**: The cipher classifications (safe/unsafe) in this tool are recommendations based on general security best practices and are not an industry standard. The security requirements for your specific use case may vary. Always:

- Consult your organization's security policies  
- Follow relevant compliance requirements (e.g., PCI DSS, HIPAA)  
- Consider the specific needs of your application  
- Consult with security professionals for production environments  

## Description

This script automates the process of checking SSL/TLS ciphers on a target domain or IP address. It uses nmap's ssl-enum-ciphers script to enumerate supported ciphers and categorizes them as safe or unsafe based on modern security standards. The results are displayed with color coding for better visibility:

- 🟢 Safe ciphers are shown in green  
- 🔴 Unsafe ciphers are shown in red  

Additionally, the script supports:

- Normalizing TLS 1.3 cipher names for better accuracy  
- Loading the safe cipher list from a local file (`recommended_ciphers.txt`)  
- Updating the safe cipher list automatically from IANA via `--update` (requires `requests` module)  

## Requirements

- Python 3.x  
- nmap installed and accessible from PATH  
- Optional: `requests` Python module for the `--update` feature  

## Installation

1. Ensure nmap is installed on your system:

   ```bash
   # For Ubuntu/Debian
   sudo apt-get install nmap

   # For CentOS/RHEL
   sudo yum install nmap

   # For macOS
   brew install nmap

   # For Windows
   Install from this link: [https://nmap.org/download.html](https://nmap.org/download.html#windows)
   ```

2. Download the script:

   ```bash
   # Option 1: Direct download
   curl -O https://raw.githubusercontent.com/Prim1Tive/TlsCipherAuditor/main/TlsCipherAuditor.py

   # Option 2: Clone the repository
   git clone https://github.com/Prim1Tive/TlsCipherAuditor.git
   cd TlsCipherAuditor
   ```

3. (Optional) Install the `requests` module to enable updating:

   ```bash
   pip install requests
   ```

4. Make the script executable:

   ```bash
   chmod +x TlsCipherAuditor.py
   ```

## Usage

You can run the script in several ways:

- **Check ciphers on a domain or IP:**

  ```bash
  python TlsCipherAuditor.py example.com
  ```

- **Interactive mode:**

  ```bash
  python TlsCipherAuditor.py
  # You will be prompted to enter domain or IP repeatedly
  ```

- **Update the safe cipher list from IANA (requires requests):**

  ```bash
  python TlsCipherAuditor.py --update
  ```

- **Show help:**

  ```bash
  python TlsCipherAuditor.py --help
  ```

## Safe Ciphers

The script loads the safe cipher list from the local file `recommended_ciphers.txt` if present. Otherwise, it falls back to a built-in default set:

- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256  
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384  
- TLS_AES_128_GCM_SHA256  
- TLS_AES_256_GCM_SHA384  
- TLS_CHACHA20_POLY1305_SHA256  
- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384  

### Customizing Safe Ciphers

- You can manually edit the `recommended_ciphers.txt` file to add or remove ciphers you consider safe.  
- Alternatively, modify the `safe_ciphers` set in the script directly.  

## Example Output

![screenshot](/image/cipher-check-output.png "Optional title")

## Changelog

### Version 0.4 (Current)
- Added customizable safe ciphers list documentation
- Updated README with detailed customization instructions
- Added disclaimer about cipher recommendations being guidelines only
- Improved documentation clarity and organization
- Added screenshot to README for visual reference
- Added detailed installation instructions for different OS
- Added proper git clone instructions
- Restructured README for better readability
- Added version tracking in changelog

### Version 0.3
- Added help command functionality (-h, --help)
- Added interactive mode with infinite loop for multiple domain checks
- Added proper error handling for keyboard interrupts and exceptions
- Added color-coded help text for better readability
- Added 'quit' and 'exit' commands for graceful termination

### Version 0.2
- Renamed script from cipher-check.py to TlsCipherAuditor.py
- Restructured code for better organization
- Added basic error handling
- Improved output formatting

### Version 0.1 (Initial Release)
- Basic TLS cipher checking functionality
- Color-coded output for safe/unsafe ciphers
- Command-line argument support
- Basic nmap integration
- Support for multiple TLS versions
