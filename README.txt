# Sidakjari - Python Edition

A modern implementation of the FOCA (Fingerprinting Organizations with Collected Archives) tool written in Python.

## Overview

Sidakjari is a powerful security tool designed to extract metadata from documents publicly available on websites. It helps security professionals and penetration testers identify potential information leakage in an organization's public documents.

The tool:
- Crawls websites to find documents (PDFs, Office documents, images, etc.)
- Downloads these documents for analysis
- Extracts metadata including usernames, emails, software versions, etc.
- Identifies internal domain names, IP addresses, and system information
- Generates detailed reports of all findings

## Features

- **Document Discovery**: Crawls target websites to find documents
- **Metadata Extraction**: Extracts valuable metadata from multiple file formats:
  - PDF
  - Microsoft Office (DOCX, XLSX, PPTX)
  - Images (JPEG, PNG, GIF)
  - XML, CSV
- **Information Analysis**: Identifies and correlates:
  - Usernames and email addresses
  - Internal domain names
  - IP addresses and network information
  - Software versions and configurations
  - File paths and server names
- **Reporting**: Generates comprehensive reports of all findings
- **Local Analysis**: Can analyze both websites and local document collections

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/modern-foca.git
cd modern-foca

# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
# Scan a website
python modern_foca.py --url https://example.com --output results

# Analyze local documents
python modern_foca.py --local ./documents --output results
```

### Advanced Options

```bash
# Increase crawl depth
python modern_foca.py --url https://example.com --depth 3

# Use more threads for faster processing
python modern_foca.py --url https://example.com --threads 20

# Full options
python modern_foca.py --help
```

### Programmatic Usage

See the [usage_examples.py](usage_examples.py) file for examples of how to use Sidakjari in your own Python scripts.

## Output

Sidakjari generates reports in the specified output directory:

```
output/
??? documents/        # Downloaded documents
??? reports/
    ??? users.txt     # Discovered users and emails
    ??? domains.txt   # Discovered domains
    ??? software.txt  # Discovered software
    ??? networks.txt  # Discovered network information
```

## Ethical Use

This tool is intended for legitimate security testing, penetration testing, and security audits with proper authorization. Always:

1. Obtain proper permission before scanning any website
2. Respect the privacy and confidentiality of any information discovered
3. Follow responsible disclosure procedures if vulnerabilities are identified
4. Comply with all applicable laws and regulations

Unauthorized use of this tool against systems without permission may violate laws.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements

This project is a modern Python implementation inspired by the original FOCA tool developed by ElevenPaths.