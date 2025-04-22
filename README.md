# TLS Cipher Auditor

A Python script that analyzes SSL/TLS ciphers using nmap's ssl-enum-ciphers script and provides a color-coded output of safe and unsafe ciphers.

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
   # Option 1: Direct download
   curl -O https://raw.githubusercontent.com/Prim1Tive/TlsCipherAuditor/main/TlsCipherAuditor.py
   
   # Option 2: Clone the repository
   git clone https://github.com/Prim1Tive/TlsCipherAuditor.git
   cd TlsCipherAuditor
   ```

3. Make the script executable:
   ```bash
   chmod +x TlsCipherAuditor.py
   ```

## Usage

You can run the script in two ways:

1. With a command-line argument:
   ```bash
   python TlsCipherAuditor.py example.com
   ```

2. Interactive mode:
   ```bash
   python TlsCipherAuditor.py
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

### Customizing Safe Ciphers

You can customize which ciphers are considered "safe" by modifying the `safe_ciphers` set in the script. The project includes a `ciphers.py` file which serves as a reference database of all cipher suites nmap can detect.

#### How to Use ciphers.py
The `ciphers.py` file is a reference file containing all possible cipher suites that nmap can detect. To use it:

1. Open `ciphers.py` to view the complete list of available cipher suites
2. Choose the cipher suites you want to consider as "safe"
3. Add these to the `safe_ciphers` set in `TlsCipherAuditor.py`:
```python
safe_ciphers = {
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    # Add your chosen ciphers from ciphers.py here
}
```

Note: `ciphers.py` is a reference file only - it contains the complete list of cipher suites that nmap can detect. Use it to look up and select the cipher suites you want to mark as safe in your environment.

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