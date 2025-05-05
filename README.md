# Sidikjari

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

## Disclaimer

This tool is for educational and research purposes only. Users are responsible for how they deploy and use this honeypot system. Always obtain proper authorization before deploying honeypots in production environments.

## Contact
For professional services, integrations, or support contact: operations@redcellsecurity.org

## License

**Author**: Keith Pachulski  
**Company**: Red Cell Security, LLC  
**Email**: keith@redcellsecurity.org  
**Website**: www.redcellsecurity.org  

© 2025 Keith Pachulski. All rights reserved.

**License**: This software is licensed under the MIT License. You are free to use, modify, and distribute this software in accordance with the terms of the license.

## Support My Work

If you find my work useful and want to support continued development, you can donate here:

[![Donate](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://paypal.me/sec0ps)

> **DISCLAIMER**:  
> This software is provided "as-is," without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement. In no event shall the authors or copyright holders
> be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.
> This tool is for educational and research purposes only. Users are responsible for how they deploy and use this honeypot system. Always obtain proper authorization before deploying honeypots in production environments.


## Acknowledgements

This project is a modern Python implementation inspired by the original FOCA tool developed by ElevenPaths.
