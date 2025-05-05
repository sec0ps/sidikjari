# =============================================================================
# Sidikjari - Python-Based Metadata Extraction Tool
# =============================================================================
#
# Author: Keith Pachulski
# Company: Red Cell Security, LLC
# Email: keith@redcellsecurity.org
# Website: www.redcellsecurity.org
#
# Copyright (c) 2025 Keith Pachulski. All rights reserved.
#
# License: This software is licensed under the MIT License.
#          You are free to use, modify, and distribute this software
#          in accordance with the terms of the license.
#
# Purpose: This module is part of the Sidikjari metadata extraction system, designed to
#          analyze documents and extract valuable metadata information.
#          It provides comprehensive metadata extraction, analysis, and reporting
#          capabilities for cybersecurity research and penetration testing.
#
# DISCLAIMER: This software is provided "as-is," without warranty of any kind,
#             express or implied, including but not limited to the warranties
#             of merchantability, fitness for a particular purpose, and non-infringement.
#             In no event shall the authors or copyright holders be liable for any claim,
#             damages, or other liability, whether in an action of contract, tort, or otherwise,
#             arising from, out of, or in connection with the software or the use or other dealings
#             in the software.
#
# =============================================================================

import os
import sys
import argparse
import concurrent.futures
import requests
import time
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import magic
import logging
from colorama import Fore, Style, init
from rich.console import Console
from rich.table import Table
from pathlib import Path
import re
import ipaddress
from collections import defaultdict
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import json
import subprocess
import shutil
from ipwhois import IPWhois
from datetime import datetime

# Metadata extraction libraries
import PyPDF2
from PIL import Image
from PIL.ExifTags import TAGS
import docx
import openpyxl
import xml.etree.ElementTree as ET
import zipfile
import csv

# For PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

# Network tools
import dns.resolver
import socket
import whois

# Initialize colorama
init()

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("Sidikjari.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("Sidikjari")
console = Console()

class Sidikjari:
    def __init__(self, target_url=None, output_dir="output", depth=2, threads=10, report_format="text", time_delay=0.0, user_agent="default"):
        # Add https:// scheme if not present and target_url is provided
        if target_url and not target_url.startswith(('http://', 'https://')):
            target_url = f'https://{target_url}'
    
        self.document_metadata = {}  # Stores detailed metadata per document
        self.document_content = {}   # Stores sample content from each document
      
        self.target_url = target_url
        self.output_dir = output_dir
        self.depth = depth
        self.threads = threads
        self.report_format = report_format  # "text", "html", or "pdf"
        self.time_delay = time_delay  # Delay between requests in seconds
        self.user_agent = self._get_user_agent(user_agent)  # User agent string
        self.visited_urls = set()
        self.document_urls = set()
        self.file_paths = set()
        
        # Metadata storage
        self.users = set()
        self.emails = set()
        self.software = set()
        self.hosts = set()
        self.internal_domains = set()
        self.ip_addresses = set()
        self.ip_info = {}  # Store detailed IP information
        self.paths = set()
        
        # Initialize exiftool path
        self.exiftool_path = shutil.which('exiftool') or "exiftool"
        
        # File extensions to look for - keep only these specific types
        self.interesting_extensions = {
            'pdf': self.extract_pdf_metadata,
            'docx': self.extract_docx_metadata,
            'xlsx': self.extract_xlsx_metadata,
            'pptx': self.extract_pptx_metadata,
            'jpg': self.extract_image_metadata,
            'jpeg': self.extract_image_metadata,
            'png': self.extract_image_metadata,
            'gif': self.extract_image_metadata,
            'csv': self.extract_csv_metadata
        }
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)

    def _get_user_agent(self, user_agent_type):
        """Select a user agent based on the specified type"""
        user_agents = {
            "default": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
            "firefox": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0",
            "safari": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15",
            "edge": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36 Edg/96.0.1054.62",
            "mobile": "Mozilla/5.0 (iPhone; CPU iPhone OS 15_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Mobile/15E148 Safari/604.1"
        }
        
        if user_agent_type == "random":
            import random
            return random.choice(list(user_agents.values()))
        
        return user_agents.get(user_agent_type, user_agents["default"])

    def crawl_website(self):
        """Crawls the target website to find documents"""
        # Ensure target URL has a scheme
        url = self.target_url
        if url and not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
            self.target_url = url  # Update the target_url with the scheme
            
        logger.info(f"{Fore.GREEN}Starting crawl of {self.target_url}{Style.RESET_ALL}")
        
        self._crawl_url(self.target_url, 0)
        
        logger.info(f"{Fore.GREEN}Crawling complete. Found {len(self.document_urls)} documents{Style.RESET_ALL}")
        
    def _crawl_url(self, url, current_depth):
        """Recursively crawl URLs up to the specified depth"""
        # Ensure URL has a scheme (add https:// if not present)
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
            
        if url in self.visited_urls or current_depth > self.depth:
            return
        
        self.visited_urls.add(url)
        
        try:
            # Implement time delay between requests if specified
            if self.time_delay > 0:
                time.sleep(self.time_delay)
            
            # Set custom headers with the selected user agent
            headers = {
                'User-Agent': self.user_agent
            }
            
            # Disable SSL certificate verification
            response = requests.get(url, timeout=10, verify=False, headers=headers)
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '')
                
                # Check if this is a document we're interested in - STRICTLY filter by extension
                file_extension = os.path.splitext(urlparse(url).path)[1].lower().replace('.', '')
                if file_extension in self.interesting_extensions:
                    self.document_urls.add(url)
                    logger.info(f"Found document to analyze: {url} ({file_extension})")
                
                # If HTML, parse links and continue crawling
                if 'text/html' in content_type:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    for link in soup.find_all('a', href=True):
                        next_url = link['href']
                        
                        # Handle relative URLs
                        if not bool(urlparse(next_url).netloc):
                            next_url = urljoin(url, next_url)
                        
                        # Ensure target_url has a scheme for comparison
                        target_domain = self.target_url
                        if not target_domain.startswith(('http://', 'https://')):
                            target_domain = f'https://{target_domain}'
                        
                        # Only follow links to the same domain
                        if urlparse(target_domain).netloc == urlparse(next_url).netloc:
                            self._crawl_url(next_url, current_depth + 1)
                            
        except Exception as e:
            logger.error(f"Error crawling {url}: {str(e)}")
    
    def download_documents(self):
        """Downloads all discovered documents for metadata extraction"""
        logger.info(f"{Fore.GREEN}Downloading {len(self.document_urls)} documents{Style.RESET_ALL}")
        
        documents_dir = os.path.join(self.output_dir, "documents")
        os.makedirs(documents_dir, exist_ok=True)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._download_document, doc_url, documents_dir): doc_url for doc_url in self.document_urls}
            
            for future in concurrent.futures.as_completed(futures):
                doc_url = futures[future]
                try:
                    file_path = future.result()
                    if file_path:
                        self.file_paths.add(file_path)
                except Exception as e:
                    logger.error(f"Error downloading {doc_url}: {str(e)}")
        
        logger.info(f"{Fore.GREEN}Downloaded {len(self.file_paths)} documents{Style.RESET_ALL}")
    
    def _download_document(self, url, output_dir):
        """Downloads a single document"""
        try:
            # Implement time delay between requests if specified
            if self.time_delay > 0:
                time.sleep(self.time_delay)
                
            # Set custom headers with the selected user agent
            headers = {
                'User-Agent': self.user_agent
            }
            
            # Disable SSL certificate verification
            response = requests.get(url, timeout=30, stream=True, verify=False, headers=headers)
            if response.status_code == 200:
                # Extract filename from URL
                filename = os.path.basename(urlparse(url).path)
                if not filename:
                    filename = f"document_{hash(url)}"
                
                file_path = os.path.join(output_dir, filename)
                
                with open(file_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                
                logger.info(f"Downloaded {url} to {file_path}")
                return file_path
            else:
                logger.warning(f"Failed to download {url}, status code: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Error downloading {url}: {str(e)}")
            return None

    def extract_all_metadata(self):
        """Extracts metadata from all downloaded files"""
        logger.info(f"{Fore.GREEN}Extracting metadata from {len(self.file_paths)} files{Style.RESET_ALL}")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._process_file, file_path): file_path for file_path in self.file_paths}
            
            for future in concurrent.futures.as_completed(futures):
                file_path = futures[future]
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error processing {file_path}: {str(e)}")
        
        self._analyze_metadata()
        
    def _process_file(self, file_path):
        """Process a single file to extract metadata"""
        try:
            # Determine file type
            extension = os.path.splitext(file_path)[1].lower().replace('.', '')
            
            # Create document metadata record if it doesn't exist
            if file_path not in self.document_metadata:
                self.document_metadata[file_path] = {
                    'filename': os.path.basename(file_path),
                    'file_path': file_path,
                    'file_size': os.path.getsize(file_path),
                    'file_type': extension,
                    'creation_date': None,
                    'modification_date': None,
                    'authors': set(),
                    'software': set(),
                    'title': None,
                    'subject': None,
                    'keywords': set(),
                    'found_emails': set(),
                    'found_urls': set(),
                    'found_paths': set(),
                    'found_hostnames': set(),
                    'found_ip_addresses': set(),
                    'creation_tool': None,
                    'os_info': None,
                    'gps_data': None,
                    'device_info': None,
                    'all_metadata': {},  # Store ALL metadata fields here
                    'exiftool_metadata': {}  # Store raw exiftool output here
                }
            
            # First run exiftool to get comprehensive metadata
            exif_metadata = self._extract_exiftool_metadata(file_path)
            
            # Get file system metadata
            self._extract_filesystem_metadata(file_path)
                    
            # Then call the specific extractor for additional format-specific extraction
            if extension in self.interesting_extensions:
                self.interesting_extensions[extension](file_path)
            else:
                logger.warning(f"No specific metadata extractor available for {file_path}")
                    
        except Exception as e:
            logger.error(f"Error processing {file_path}: {str(e)}")
    
    def _flatten_metadata(self, metadata, prefix=''):
        """Flatten nested metadata dictionaries for easier access and reporting"""
        result = {}
        if not metadata or not isinstance(metadata, dict):
            return result
            
        for key, value in metadata.items():
            new_key = f"{prefix}{key}" if prefix else key
            if isinstance(value, dict):
                result.update(self._flatten_metadata(value, f"{new_key}."))
            elif isinstance(value, list):
                # Handle lists by converting them to strings
                if all(isinstance(item, dict) for item in value):
                    # If list contains dictionaries, flatten each one
                    for i, item in enumerate(value):
                        result.update(self._flatten_metadata(item, f"{new_key}[{i}]."))
                else:
                    # Otherwise join the list elements
                    result[new_key] = ", ".join(str(item) for item in value)
            else:
                result[new_key] = value
        return result
    
    def _extract_filesystem_metadata(self, file_path):
        """Extract metadata from the file system"""
        try:
            stat_info = os.stat(file_path)
            
            # Creation time (platform dependent)
            if hasattr(stat_info, 'st_birthtime'):  # macOS
                creation_time = datetime.fromtimestamp(stat_info.st_birthtime)
            else:  # Fallback to ctime which might be change time on some systems
                creation_time = datetime.fromtimestamp(stat_info.st_ctime)
            
            # Modification and access times
            modification_time = datetime.fromtimestamp(stat_info.st_mtime)
            access_time = datetime.fromtimestamp(stat_info.st_atime)
            
            # Store in document metadata
            if file_path in self.document_metadata:
                self.document_metadata[file_path]['all_metadata']['filesystem.creation_time'] = creation_time.isoformat()
                self.document_metadata[file_path]['all_metadata']['filesystem.modification_time'] = modification_time.isoformat()
                self.document_metadata[file_path]['all_metadata']['filesystem.access_time'] = access_time.isoformat()
                self.document_metadata[file_path]['all_metadata']['filesystem.size'] = stat_info.st_size
                self.document_metadata[file_path]['all_metadata']['filesystem.permissions'] = stat_info.st_mode
                
                # If no creation date from metadata, use filesystem creation time
                if not self.document_metadata[file_path]['creation_date']:
                    self.document_metadata[file_path]['creation_date'] = creation_time.isoformat()
                    
                # If no modification date from metadata, use filesystem modification time
                if not self.document_metadata[file_path]['modification_date']:
                    self.document_metadata[file_path]['modification_date'] = modification_time.isoformat()
                    
        except Exception as e:
            logger.error(f"Error extracting filesystem metadata for {file_path}: {str(e)}")
    
    def _extract_exiftool_metadata(self, file_path):
        """Extract complete metadata using exiftool"""
        metadata = {}
        try:
            # Run exiftool with all metadata options
            # -a (extract duplicate tags)
            # -u (extract unknown tags)
            # -g (group output by tag category)
            # -j (JSON output)
            # -x (exclude thumbnail data which can be large)
            cmd = [self.exiftool_path, '-a', '-u', '-g', '-j', '-x', 'Thumbnail*', file_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout:
                # Parse JSON output
                try:
                    exif_data = json.loads(result.stdout)
                    if exif_data and isinstance(exif_data, list) and len(exif_data) > 0:
                        metadata = exif_data[0]
                        
                        # Store all metadata in the document record
                        if file_path in self.document_metadata:
                            # Store the raw exiftool output
                            self.document_metadata[file_path]['exiftool_metadata'] = metadata
                            
                            # Store ALL fields in a flattened structure for easy access
                            flattened = self._flatten_metadata(metadata)
                            self.document_metadata[file_path]['all_metadata'] = flattened
                        
                        # Extract key information for our collections
                        self._process_key_metadata_fields(file_path, metadata)
                        
                        # Log metadata fields found for debugging
                        logger.debug(f"Extracted {len(flattened)} metadata fields from {file_path}")
                        
                except json.JSONDecodeError:
                    logger.error(f"Error parsing exiftool JSON output for {file_path}")
            
            # If we didn't get any metadata, try again with different options
            if not metadata:
                cmd = [self.exiftool_path, '-j', '-a', '-u', file_path]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0 and result.stdout:
                    try:
                        exif_data = json.loads(result.stdout)
                        if exif_data and isinstance(exif_data, list) and len(exif_data) > 0:
                            metadata = exif_data[0]
                            
                            # Store all metadata in the document record
                            if file_path in self.document_metadata:
                                self.document_metadata[file_path]['exiftool_metadata'] = metadata
                                
                                # Store ALL fields in a flattened structure for easy access
                                flattened = self._flatten_metadata(metadata)
                                self.document_metadata[file_path]['all_metadata'] = flattened
                            
                            # Extract key information for our collections
                            self._process_key_metadata_fields(file_path, metadata)
                    except json.JSONDecodeError:
                        logger.error(f"Error parsing fallback exiftool JSON output for {file_path}")
            
        except Exception as e:
            logger.error(f"Error running exiftool on {file_path}: {str(e)}")
        
        return metadata
    
    def _process_key_metadata_fields(self, file_path, metadata):
        """Process key metadata fields for intelligence gathering"""
        # Flatten nested metadata structure if needed
        flat_metadata = {}
        for group_key, group_data in metadata.items():
            if isinstance(group_data, dict):
                for field_key, field_value in group_data.items():
                    flat_metadata[f"{group_key}:{field_key}"] = field_value
            else:
                flat_metadata[group_key] = group_data
        
        # Look for author/creator information (different naming across file formats)
        author_fields = ['Author', 'Creator', 'Artist', 'Owner', 'By-line', 
                         'OwnerName', 'Microsoft:Author', 'XMP:Creator', 
                         'EXIF:Artist', 'ID3:Artist', 'PDF:Author']
        
        for field in author_fields:
            value = self._get_nested_field(metadata, field)
            if value:
                if isinstance(value, list):
                    for author in value:
                        if author:
                            self.users.add(author)
                            if file_path in self.document_metadata:
                                self.document_metadata[file_path]['authors'].add(author)
                else:
                    self.users.add(value)
                    if file_path in self.document_metadata:
                        self.document_metadata[file_path]['authors'].add(value)
        
        # Look for software information
        software_fields = ['Software', 'Producer', 'CreatorTool', 'Generator', 
                           'Application', 'SourceProgram', 'PDF:Producer', 
                           'XMP:CreatorTool', 'APP14:Adobe']
        
        for field in software_fields:
            value = self._get_nested_field(metadata, field)
            if value:
                if isinstance(value, list):
                    for sw in value:
                        if sw:
                            self.software.add(sw)
                            if file_path in self.document_metadata:
                                self.document_metadata[file_path]['software'].add(sw)
                else:
                    self.software.add(value)
                    if file_path in self.document_metadata:
                        self.document_metadata[file_path]['software'].add(value)
        
        # Look for title information
        title_fields = ['Title', 'DocumentName', 'Headline', 'ObjectName', 
                        'XMP:Title', 'PDF:Title', 'ID3:Title']
        
        for field in title_fields:
            value = self._get_nested_field(metadata, field)
            if value and file_path in self.document_metadata:
                self.document_metadata[file_path]['title'] = value
                break
        
        # Look for subject/description information
        subject_fields = ['Subject', 'Description', 'Caption', 'Comment', 
                          'XMP:Description', 'PDF:Subject', 'ID3:Comment']
        
        for field in subject_fields:
            value = self._get_nested_field(metadata, field)
            if value and file_path in self.document_metadata:
                self.document_metadata[file_path]['subject'] = value
                break
        
        # Look for dates
        creation_date_fields = ['CreateDate', 'DateTimeOriginal', 'CreationDate', 
                               'DateCreated', 'PDF:CreationDate', 'XMP:CreateDate']
        
        for field in creation_date_fields:
            value = self._get_nested_field(metadata, field)
            if value and file_path in self.document_metadata:
                self.document_metadata[file_path]['creation_date'] = value
                break
        
        modification_date_fields = ['ModifyDate', 'FileModifyDate', 'ModificationDate', 
                                   'PDF:ModDate', 'XMP:ModifyDate']
        
        for field in modification_date_fields:
            value = self._get_nested_field(metadata, field)
            if value and file_path in self.document_metadata:
                self.document_metadata[file_path]['modification_date'] = value
                break
        
        # Extract GPS coordinates if available
        gps_fields = {
            'lat': ['GPSLatitude', 'GPS:GPSLatitude', 'XMP:GPSLatitude'],
            'lon': ['GPSLongitude', 'GPS:GPSLongitude', 'XMP:GPSLongitude'],
            'alt': ['GPSAltitude', 'GPS:GPSAltitude', 'XMP:GPSAltitude']
        }
        
        gps_data = {}
        for coord_type, fields in gps_fields.items():
            for field in fields:
                value = self._get_nested_field(metadata, field)
                if value:
                    gps_data[coord_type] = value
                    break
        
        if gps_data and file_path in self.document_metadata:
            self.document_metadata[file_path]['gps_data'] = gps_data
        
        # Look for device information
        device_fields = ['Model', 'Make', 'DeviceManufacturer', 'DeviceModel', 
                         'EXIF:Make', 'EXIF:Model', 'XMP:Device']
        
        device_info = {}
        for field in device_fields:
            value = self._get_nested_field(metadata, field)
            if value:
                device_info[field] = value
        
        if device_info and file_path in self.document_metadata:
            self.document_metadata[file_path]['device_info'] = device_info
    
    def _get_nested_field(self, metadata, field_path):
        """Get a field value from potentially nested metadata structure"""
        parts = field_path.split(':')
        
        # Direct field access
        if len(parts) == 1 and field_path in metadata:
            return metadata[field_path]
        
        # Nested field access
        if len(parts) > 1:
            current = metadata
            for part in parts:
                if part in current:
                    current = current[part]
                else:
                    return None
            return current
        
        return None

    def extract_csv_metadata(self, file_path):
        """Extract metadata from CSV files"""
        try:
            with open(file_path, 'r', newline='', encoding='utf-8-sig') as f:
                csv_reader = csv.reader(f)
                for row in csv_reader:
                    for cell in row:
                        if cell and isinstance(cell, str):
                            self._extract_from_text(cell)
        
        except Exception as e:
            logger.error(f"Error extracting CSV metadata from {file_path}: {str(e)}")

    def extract_pdf_metadata(self, file_path):
        """Extract enhanced metadata from PDF files"""
        try:
            with open(file_path, 'rb') as f:
                pdf = PyPDF2.PdfReader(f)
                info = pdf.metadata
                
                # Create document metadata record if it doesn't exist
                if file_path not in self.document_metadata:
                    self.document_metadata[file_path] = {
                        'filename': os.path.basename(file_path),
                        'file_path': file_path,
                        'file_size': os.path.getsize(file_path),
                        'file_type': 'pdf',
                        'creation_date': None,
                        'modification_date': None,
                        'authors': set(),
                        'software': set(),
                        'title': None,
                        'subject': None,
                        'keywords': set(),
                        'found_emails': set(),
                        'found_urls': set(),
                        'found_paths': set(),
                        'found_hostnames': set(),
                        'found_ip_addresses': set(),
                        'all_metadata': {},  # Store ALL metadata fields here
                        'exiftool_metadata': {}  # Store raw exiftool output here
                    }
                
                # Process PDF metadata if available
                if info:
                    # Basic metadata fields
                    if hasattr(info, 'author') and info.author:
                        self.document_metadata[file_path]['authors'].add(info.author)
                        self.users.add(info.author)
                    
                    if hasattr(info, 'creator') and info.creator:
                        self.document_metadata[file_path]['software'].add(info.creator)
                        self.software.add(info.creator)
                        # Look for potential usernames in creator field
                        if '\\' in info.creator:
                            parts = info.creator.split('\\')
                            if len(parts) > 1:
                                self.users.add(parts[1])
                                self.document_metadata[file_path]['authors'].add(parts[1])
                    
                    if hasattr(info, 'title') and info.title:
                        self.document_metadata[file_path]['title'] = info.title
                    
                    if hasattr(info, 'subject') and info.subject:
                        self.document_metadata[file_path]['subject'] = info.subject
                    
                    if hasattr(info, 'producer') and info.producer:
                        self.document_metadata[file_path]['software'].add(info.producer)
                        self.software.add(info.producer)
                    
                    # Parse creation and modification dates
                    if '/CreationDate' in info:
                        date_str = info['/CreationDate']
                        if isinstance(date_str, str) and date_str.startswith('D:'):
                            self.document_metadata[file_path]['creation_date'] = date_str[2:14]  # Extract date part
                    
                    if '/ModDate' in info:
                        date_str = info['/ModDate']
                        if isinstance(date_str, str) and date_str.startswith('D:'):
                            self.document_metadata[file_path]['modification_date'] = date_str[2:14]  # Extract date part
                    
                    # Check for all metadata fields - process dictionary
                    for key in info:
                        try:
                            value = info[key]
                            if isinstance(value, str):
                                # Store in all_metadata
                                self.document_metadata[file_path]['all_metadata'][key] = value
                                
                                # Extract emails, URLs, and paths from metadata
                                emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', value)
                                urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', value)
                                paths = re.findall(r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*', value)
                                
                                if emails:
                                    self.document_metadata[file_path]['found_emails'].update(emails)
                                    self.emails.update(emails)
                                
                                if urls:
                                    self.document_metadata[file_path]['found_urls'].update(urls)
                                
                                if paths:
                                    self.document_metadata[file_path]['found_paths'].update(paths)
                                    self.paths.update(paths)
                        except Exception as sub_e:
                            logger.debug(f"Error processing metadata field {key}: {sub_e}")
                
                # Also run exiftool for more comprehensive metadata
                exiftool_metadata = self._extract_exiftool_metadata(file_path)
                if exiftool_metadata:
                    # Merge with existing metadata
                    if 'all_metadata' not in self.document_metadata[file_path]:
                        self.document_metadata[file_path]['all_metadata'] = {}
                    
                    flat_metadata = self._flatten_metadata(exiftool_metadata)
                    self.document_metadata[file_path]['all_metadata'].update(flat_metadata)
                
                # Extract text content for further analysis
                extracted_text = ""
                try:
                    for page_num in range(len(pdf.pages)):
                        page = pdf.pages[page_num]
                        text = page.extract_text()
                        if text:
                            extracted_text += text + "\n"
                            self._extract_from_text(text)
                except Exception as text_e:
                    logger.debug(f"Error extracting text from PDF {file_path}: {text_e}")
                
                # Store summary of extracted text for later analysis
                text_sample = extracted_text[:2000] if len(extracted_text) > 2000 else extracted_text
                self.document_content[file_path] = text_sample
                    
        except Exception as e:
            logger.error(f"Error extracting PDF metadata from {file_path}: {str(e)}")

    def extract_docx_metadata(self, file_path):
        """Extract metadata from DOCX files"""
        try:
            doc = docx.Document(file_path)
            core_props = doc.core_properties
            
            # Extract creator info
            if core_props.author:
                self.users.add(core_props.author)
            if core_props.last_modified_by:
                self.users.add(core_props.last_modified_by)
                
            # Extract app version
            if hasattr(core_props, 'revision') and core_props.revision:
                self.software.add(f"Microsoft Word - {core_props.revision}")
            
            # Extract text for further analysis
            for para in doc.paragraphs:
                self._extract_from_text(para.text)
            
        except Exception as e:
            logger.error(f"Error extracting DOCX metadata from {file_path}: {str(e)}")

    def extract_xlsx_metadata(self, file_path):
        """Extract metadata from XLSX files"""
        try:
            wb = openpyxl.load_workbook(file_path, read_only=True, data_only=True)
            
            # Extract metadata from workbook properties
            if wb.properties.creator:
                self.users.add(wb.properties.creator)
            if wb.properties.lastModifiedBy:
                self.users.add(wb.properties.lastModifiedBy)
            
            # Extract text from each sheet
            for sheet_name in wb.sheetnames:
                sheet = wb[sheet_name]
                for row in sheet.iter_rows():
                    for cell in row:
                        if cell.value and isinstance(cell.value, str):
                            self._extract_from_text(cell.value)
            
        except Exception as e:
            logger.error(f"Error extracting XLSX metadata from {file_path}: {str(e)}")

    def extract_pptx_metadata(self, file_path):
        """Extract metadata from PPTX files"""
        try:
            # PPTX files are ZIP files with XML content
            with zipfile.ZipFile(file_path) as zf:
                # Extract core properties
                if 'docProps/core.xml' in zf.namelist():
                    with zf.open('docProps/core.xml') as f:
                        xml_content = f.read()
                        root = ET.fromstring(xml_content)
                        
                        # Extract creator
                        creator = root.find('.//{http://purl.org/dc/elements/1.1/}creator')
                        if creator is not None and creator.text:
                            self.users.add(creator.text)
                        
                        # Extract last modified by
                        last_modified_by = root.find('.//{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}lastModifiedBy')
                        if last_modified_by is not None and last_modified_by.text:
                            self.users.add(last_modified_by.text)
                
                # Extract app properties
                if 'docProps/app.xml' in zf.namelist():
                    with zf.open('docProps/app.xml') as f:
                        xml_content = f.read()
                        root = ET.fromstring(xml_content)
                        
                        # Extract application
                        application = root.find('.//{http://schemas.openxmlformats.org/officeDocument/2006/extended-properties}Application')
                        if application is not None and application.text:
                            self.software.add(application.text)
                
                # Extract slide content
                for name in zf.namelist():
                    if re.match(r'ppt/slides/slide[0-9]+\.xml', name):
                        with zf.open(name) as f:
                            xml_content = f.read()
                            root = ET.fromstring(xml_content)
                            
                            # Extract text from each text run in slide
                            for text_node in root.findall('.//*[@type="txBody"]//a:t', 
                                                        namespaces={'a': 'http://schemas.openxmlformats.org/drawingml/2006/main'}):
                                if text_node.text:
                                    self._extract_from_text(text_node.text)
        
        except Exception as e:
            logger.error(f"Error extracting PPTX metadata from {file_path}: {str(e)}")

    def extract_image_metadata(self, file_path):
        """Extract metadata from image files (EXIF data)"""
        try:
            with Image.open(file_path) as img:
                exif_data = img._getexif()
                
                if exif_data:
                    for tag_id, value in exif_data.items():
                        tag = TAGS.get(tag_id, tag_id)
                        
                        # Look for interesting EXIF tags
                        if tag in ['Make', 'Model', 'Software']:
                            self.software.add(f"{tag}: {value}")
                        elif tag in ['Artist', 'Copyright', 'ImageDescription']:
                            if isinstance(value, str):
                                self.users.add(value)
                                self._extract_from_text(value)
                        
                        # Some cameras/phones store GPS data
                        elif tag == 'GPSInfo':
                            # Process GPS data if needed
                            pass
        
        except Exception as e:
            logger.error(f"Error extracting image metadata from {file_path}: {str(e)}")

    def _extract_from_text(self, text):
        """Extract useful information from text content"""
        if not text or not isinstance(text, str):
            return
        
        # Extract email addresses
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, text)
        for email in emails:
            self.emails.add(email)
            # Extract domain from email
            domain = email.split('@')[1]
            self.internal_domains.add(domain)
        
        # Extract potential internal domain names
        domain_pattern = r'(?:https?://)?(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?:/[^\s]*)?'
        domains = re.findall(domain_pattern, text)
        for domain in domains:
            if not any(public_domain in domain for public_domain in ['google.com', 'microsoft.com', 'yahoo.com']):
                self.internal_domains.add(domain)
        
        # Extract potential file paths
        path_pattern = r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*'
        paths = re.findall(path_pattern, text)
        for path in paths:
            self.paths.add(path)
            # Extract potential username from path
            if 'Users\\' in path:
                parts = path.split('Users\\')
                if len(parts) > 1:
                    user_path = parts[1].split('\\')[0]
                    if user_path and user_path not in ['Public', 'All Users', 'Default']:
                        self.users.add(user_path)
        
        # Extract potential IP addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, text)
        for ip in ips:
            try:
                # Validate IP address
                ipaddress.ip_address(ip)
                # Exclude common non-internal IPs
                if not ip.startswith(('127.', '255.', '0.')):
                    self.ip_addresses.add(ip)
            except ValueError:
                pass
        
        # Extract hostnames (server names)
        hostname_pattern = r'\b([a-zA-Z0-9-]{2,}(?:\.[a-zA-Z0-9-]+)*)\b'
        for match in re.finditer(hostname_pattern, text):
            hostname = match.group(1)
            if len(hostname) > 2 and not any(c.isdigit() for c in hostname):
                if re.match(r'^[a-zA-Z0-9-]+$', hostname):
                    # Exclude common words
                    common_words = ['http', 'https', 'www', 'com', 'net', 'org']
                    if hostname.lower() not in common_words:
                        self.hosts.add(hostname)

    def _analyze_metadata(self):
        """Analyze collected metadata to find relationships"""
        logger.info(f"{Fore.GREEN}Analyzing collected metadata{Style.RESET_ALL}")
        
        # Group data by domain
        domain_data = defaultdict(lambda: {
            'users': set(),
            'emails': set(),
            'hosts': set(),
            'ips': set(),
            'software': set()
        })
        
        # Process emails
        for email in self.emails:
            if '@' in email:
                username, domain = email.split('@')
                domain_data[domain]['users'].add(username)
                domain_data[domain]['emails'].add(email)
        
        # Process domains and IPs
        for domain in self.internal_domains:
            try:
                # Try to resolve domain to IP
                answers = dns.resolver.resolve(domain, 'A')
                for answer in answers:
                    ip = answer.to_text()
                    domain_data[domain]['ips'].add(ip)
                    self.ip_addresses.add(ip)
            except:
                pass
        
        # Generate domain report
        self.generate_reports(domain_data) 

    def generate_reports(self, domain_data=None):
        """Generate reports in the requested format(s)"""
        logger.info(f"{Fore.GREEN}Generating reports{Style.RESET_ALL}")
        
        # Store domain_data as a class attribute if provided
        if domain_data:
            self.domain_data = domain_data
        
        # Determine which formats to generate based on class attributes
        formats_to_generate = []
        if hasattr(self, 'report_formats') and self.report_formats:
            formats_to_generate = self.report_formats
        else:
            formats_to_generate = [self.report_format]
        
        generated_reports = []
        
        # Determine the target domain from target_url if available
        target_domain = None
        if self.target_url:
            parsed_url = urlparse(self.target_url)
            target_domain = parsed_url.netloc.lower()
            if target_domain.startswith('www.'):
                target_domain = target_domain[4:]
        
        # If we have a target domain, preprocess WHOIS data
        domain_info = None
        if target_domain:
            try:
                # Force WHOIS data collection before report generation
                domain_info = self._analyze_domain_info(target_domain)
                logger.info(f"Collected WHOIS data for {target_domain}")
                # Log the data for debugging
                logger.debug(f"WHOIS data: {domain_info}")
            except Exception as e:
                logger.error(f"Error collecting WHOIS data: {str(e)}")
        
        # Generate reports in each requested format
        for format_type in formats_to_generate:
            # Use the correct file extension for each format
            if format_type == "text":
                file_extension = "txt"
            else:
                file_extension = format_type
                
            report_filename = f"Sidikjari_report.{file_extension}"
            report_path = os.path.join(self.output_dir, report_filename)
            
            try:
                if format_type == "text":
                    self._generate_text_report(report_path, target_domain, domain_info)
                elif format_type == "html":
                    self._generate_html_report(report_path, target_domain, domain_info)
                elif format_type == "pdf":
                    self._generate_pdf_report(report_path, target_domain, domain_info)
                else:
                    logger.error(f"Unknown report format: {format_type}")
                    continue
                
                generated_reports.append(report_path)
                logger.info(f"{Fore.GREEN}Report generated: {report_path}{Style.RESET_ALL}")
            except Exception as e:
                logger.error(f"Error generating {format_type} report: {str(e)}")
                # Print traceback for debugging
                import traceback
                logger.error(traceback.format_exc())
        
        return generated_reports

    def _generate_pdf_report(self, report_path, target_domain):
        """Generate a PDF report using ReportLab"""
        try:
            doc = SimpleDocTemplate(report_path, pagesize=letter)
            styles = getSampleStyleSheet()
            elements = []
            
            # Create custom style with a unique name to avoid conflicts
            custom_heading_style = ParagraphStyle(
                name='CustomHeading3',
                parent=styles['Heading2'],
                fontSize=14,
                spaceAfter=6
            )
            styles.add(custom_heading_style)
            
            # Title
            title_style = styles["Title"]
            elements.append(Paragraph("Sidikjari Metadata Analysis Report", title_style))
            elements.append(Spacer(1, 12))
            
            # Target Information
            elements.append(Paragraph(f"Target: {self.target_url if self.target_url else self.input_dir}", styles["Normal"]))
            elements.append(Spacer(1, 12))
            
            # Domain Information Section
            if target_domain and target_domain in self.internal_domains:
                domain_info = self._analyze_domain_info(target_domain)
                
                elements.append(Paragraph("DOMAIN INFORMATION", styles["Heading1"]))
                elements.append(Paragraph(f"Domain: {target_domain}", styles["Normal"]))
                elements.append(Spacer(1, 12))
                
                # Registrant Information
                elements.append(Paragraph("Registrant Information", styles["Heading2"]))
                data = []
                if domain_info['registrant']['name']:
                    data.append(["Name", domain_info['registrant']['name']])
                if domain_info['registrant']['organization']:
                    data.append(["Organization", domain_info['registrant']['organization']])
                if domain_info['registrant']['email']:
                    data.append(["Email", domain_info['registrant']['email']])
                if domain_info['registrant']['phone']:
                    data.append(["Phone", domain_info['registrant']['phone']])
                if domain_info['registrant']['fax']:
                    data.append(["Fax", domain_info['registrant']['fax']])
                if domain_info['registrant']['street']:
                    data.append(["Street", domain_info['registrant']['street']])
                if domain_info['registrant']['city']:
                    data.append(["City", domain_info['registrant']['city']])
                if domain_info['registrant']['state']:
                    data.append(["State/Province", domain_info['registrant']['state']])
                if domain_info['registrant']['postal_code']:
                    data.append(["Postal Code", domain_info['registrant']['postal_code']])
                if domain_info['registrant']['country']:
                    data.append(["Country", domain_info['registrant']['country']])
                    
                if data:
                    t = Table(data, colWidths=[100, 400])
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ]))
                    elements.append(t)
                elements.append(Spacer(1, 12))
                
                # Admin Information
                elements.append(Paragraph("Admin Information", styles["Heading2"]))
                data = []
                if domain_info['admin']['name']:
                    data.append(["Name", domain_info['admin']['name']])
                if domain_info['admin']['organization']:
                    data.append(["Organization", domain_info['admin']['organization']])
                if domain_info['admin']['email']:
                    data.append(["Email", domain_info['admin']['email']])
                if domain_info['admin']['phone']:
                    data.append(["Phone", domain_info['admin']['phone']])
                if domain_info['admin']['fax']:
                    data.append(["Fax", domain_info['admin']['fax']])
                if domain_info['admin']['street']:
                    data.append(["Street", domain_info['admin']['street']])
                if domain_info['admin']['city']:
                    data.append(["City", domain_info['admin']['city']])
                if domain_info['admin']['state']:
                    data.append(["State/Province", domain_info['admin']['state']])
                if domain_info['admin']['postal_code']:
                    data.append(["Postal Code", domain_info['admin']['postal_code']])
                if domain_info['admin']['country']:
                    data.append(["Country", domain_info['admin']['country']])
                    
                if data:
                    t = Table(data, colWidths=[100, 400])
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ]))
                    elements.append(t)
                elements.append(Spacer(1, 12))
                
                # Tech Information
                elements.append(Paragraph("Tech Information", styles["Heading2"]))
                data = []
                if domain_info['tech']['name']:
                    data.append(["Name", domain_info['tech']['name']])
                if domain_info['tech']['organization']:
                    data.append(["Organization", domain_info['tech']['organization']])
                if domain_info['tech']['email']:
                    data.append(["Email", domain_info['tech']['email']])
                if domain_info['tech']['phone']:
                    data.append(["Phone", domain_info['tech']['phone']])
                if domain_info['tech']['fax']:
                    data.append(["Fax", domain_info['tech']['fax']])
                if domain_info['tech']['street']:
                    data.append(["Street", domain_info['tech']['street']])
                if domain_info['tech']['city']:
                    data.append(["City", domain_info['tech']['city']])
                if domain_info['tech']['state']:
                    data.append(["State/Province", domain_info['tech']['state']])
                if domain_info['tech']['postal_code']:
                    data.append(["Postal Code", domain_info['tech']['postal_code']])
                if domain_info['tech']['country']:
                    data.append(["Country", domain_info['tech']['country']])
                    
                if data:
                    t = Table(data, colWidths=[100, 400])
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ]))
                    elements.append(t)
                elements.append(Spacer(1, 12))
                
                # General domain information
                elements.append(Paragraph("Domain Details", styles["Heading2"]))
                data = []
                if domain_info['registrar']:
                    data.append(["Registrar", domain_info['registrar']])
                if domain_info['creation_date']:
                    data.append(["Creation Date", str(domain_info['creation_date'])])
                if domain_info['update_date']:
                    data.append(["Updated Date", str(domain_info['update_date'])])
                if domain_info['expiration_date']:
                    data.append(["Expiration Date", str(domain_info['expiration_date'])])
                    
                if data:
                    t = Table(data, colWidths=[100, 400])
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ]))
                    elements.append(t)
                elements.append(Spacer(1, 12))
                
                # Domain Status
                if domain_info['domain_status']:
                    elements.append(Paragraph("Domain Status", custom_heading_style))
                    status_text = "\n".join([f"• {status}" for status in domain_info['domain_status']])
                    elements.append(Paragraph(status_text, styles["Normal"]))
                    elements.append(Spacer(1, 8))
                
                # Name Servers
                if domain_info['name_servers']:
                    elements.append(Paragraph("Name Servers", custom_heading_style))
                    ns_text = "\n".join([f"• {ns}" for ns in domain_info['name_servers']])
                    elements.append(Paragraph(ns_text, styles["Normal"]))
                    elements.append(Spacer(1, 12))
                
                # IP Address Information
                elements.append(Paragraph("IP ADDRESS INFORMATION", styles["Heading1"]))
                
                for ip in domain_info['ip_addresses']:
                    elements.append(Paragraph(f"{target_domain} -> {ip}", styles["Heading2"]))
                    
                    if ip in self.ip_info:
                        ip_data = self.ip_info[ip]
                        data = []
                        if ip_data['cidr']:
                            data.append(["IP CIDR", ip_data['cidr']])
                        if ip_data['asn']:
                            asn_info = f"{ip_data['asn']}"
                            if ip_data['organization']:
                                asn_info += f" ({ip_data['organization']})"
                            data.append(["Origin AS", asn_info])
                        if ip_data['country']:
                            data.append(["Country", ip_data['country']])
                        if ip_data['reverse_dns']:
                            data.append(["Reverse DNS", ip_data['reverse_dns']])
                            
                        if data:
                            t = Table(data, colWidths=[100, 400])
                            t.setStyle(TableStyle([
                                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                            ]))
                            elements.append(t)
                    elements.append(Spacer(1, 12))
            
            # Document Metadata section
            elements.append(Paragraph("DOCUMENT METADATA INFORMATION", styles["Heading1"]))
            
            for file_path, metadata in self.document_metadata.items():
                filename = os.path.basename(file_path)
                file_type = os.path.splitext(filename)[1].lower().replace('.', '')
                
                elements.append(Paragraph(f"File: {filename}", styles["Heading2"]))
                
                data = [
                    ["File Type", file_type],
                    ["File Size", f"{metadata['file_size']} bytes"]
                ]
                
                if metadata['title']:
                    data.append(["Title", metadata['title']])
                if metadata['subject']:
                    data.append(["Subject", metadata['subject']])
                if metadata['creation_date']:
                    data.append(["Creation Date", str(metadata['creation_date'])])
                if metadata['modification_date']:
                    data.append(["Modification Date", str(metadata['modification_date'])])
                    
                t = Table(data, colWidths=[150, 350])
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))
                elements.append(t)
                elements.append(Spacer(1, 8))
                
                # Authors
                if metadata['authors']:
                    elements.append(Paragraph("Authors/Users:", custom_heading_style))
                    authors_text = ", ".join(sorted(metadata['authors']))
                    elements.append(Paragraph(authors_text, styles["Normal"]))
                    elements.append(Spacer(1, 8))
                
                # Software
                if metadata['software']:
                    elements.append(Paragraph("Software Used:", custom_heading_style))
                    sw_text = ", ".join(sorted(metadata['software']))
                    elements.append(Paragraph(sw_text, styles["Normal"]))
                    elements.append(Spacer(1, 8))
                
                # Emails
                if metadata['found_emails']:
                    elements.append(Paragraph("Emails Found:", custom_heading_style))
                    email_text = ", ".join(sorted(metadata['found_emails']))
                    elements.append(Paragraph(email_text, styles["Normal"]))
                    elements.append(Spacer(1, 8))
                
                # URLs
                if metadata['found_urls']:
                    elements.append(Paragraph("URLs Found:", custom_heading_style))
                    urls_text = ", ".join(sorted(metadata['found_urls']))
                    elements.append(Paragraph(urls_text, styles["Normal"]))
                    elements.append(Spacer(1, 8))
                
                # Paths
                if metadata['found_paths']:
                    elements.append(Paragraph("Paths Found:", custom_heading_style))
                    paths_text = ", ".join(sorted(metadata['found_paths']))
                    elements.append(Paragraph(paths_text, styles["Normal"]))
                    elements.append(Spacer(1, 8))
                
                # GPS data
                if 'gps_data' in metadata and metadata['gps_data']:
                    elements.append(Paragraph("GPS Coordinates:", custom_heading_style))
                    gps_data = metadata['gps_data']
                    gps_text = []
                    if 'lat' in gps_data:
                        gps_text.append(f"Latitude: {gps_data['lat']}")
                    if 'lon' in gps_data:
                        gps_text.append(f"Longitude: {gps_data['lon']}")
                    if 'alt' in gps_data:
                        gps_text.append(f"Altitude: {gps_data['alt']}")
                    elements.append(Paragraph(", ".join(gps_text), styles["Normal"]))
                    elements.append(Spacer(1, 8))
                
                # All Metadata Fields - FULL DETAILED LISTING
                elements.append(Paragraph("All Metadata Fields:", custom_heading_style))
                
                # Get the flattened metadata
                flattened = {}
                if 'all_metadata' in metadata and metadata['all_metadata']:
                    flattened = metadata['all_metadata']
                elif 'exiftool_metadata' in metadata and metadata['exiftool_metadata']:
                    flattened = self._flatten_metadata(metadata['exiftool_metadata'])
                
                # Check if we have any metadata to display
                if flattened:
                    # Convert to list of key-value pairs and sort by key
                    all_data = [[key, str(value)] for key, value in sorted(flattened.items()) if value is not None]
                    
                    # Split into chunks to avoid overly long tables that might not fit on a page
                    chunk_size = 20
                    for i in range(0, len(all_data), chunk_size):
                        data_chunk = all_data[i:i+chunk_size]
                        t = Table(data_chunk, colWidths=[150, 350])
                        t.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ]))
                        elements.append(t)
                        elements.append(Spacer(1, 4))  # Small spacer between table chunks
                else:
                    elements.append(Paragraph("No detailed metadata available", styles["Normal"]))
                
                elements.append(Spacer(1, 12))
            
            # Footer
            footer_style = ParagraphStyle(
                'Footer',
                parent=styles['Normal'],
                fontSize=8,
                textColor=colors.grey,
                alignment=1
            )
            elements.append(Spacer(1, 20))
            elements.append(Paragraph("Report generated by Sidikjari - Metadata Extraction Tool", footer_style))
            elements.append(Paragraph("Red Cell Security, LLC - www.redcellsecurity.org", footer_style))
            
            # Build the PDF
            doc.build(elements)
            logger.info(f"PDF report generated: {report_path}")
            
        except Exception as e:
            logger.error(f"Error generating PDF report: {str(e)}")

    def _generate_text_report(self, report_path, target_domain, domain_info=None):
        """Generate a detailed text report with domain information"""
        with open(report_path, 'w') as f:
            f.write("SIDIKJARI METADATA ANALYSIS REPORT\n")
            f.write("================================\n\n")
            
            # Target information
            f.write(f"Target: {self.target_url if self.target_url else self.input_dir}\n\n")
            
            # Domain Information
            if target_domain:
                # If domain_info was not provided, try to get it now
                if domain_info is None:
                    try:
                        domain_info = self._analyze_domain_info(target_domain)
                    except Exception as e:
                        f.write(f"Error collecting domain info: {str(e)}\n\n")
                
                if domain_info:
                    f.write("DOMAIN INFORMATION\n")
                    f.write("-----------------\n\n")
                    f.write(f"Domain: {target_domain}\n\n")
                    
                    # Registrant Information
                    f.write("Registrant Information:\n")
                    
                    # Debug info - uncomment for troubleshooting
                    # f.write(f"DEBUG - Registrant fields available: {', '.join([k for k, v in domain_info['registrant'].items() if v])}\n")
                    
                    for field, label in [
                        ('name', 'Name'),
                        ('organization', 'Organization'),
                        ('email', 'Email'),
                        ('phone', 'Phone'),
                        ('fax', 'Fax'),
                        ('street', 'Street'),
                        ('city', 'City'),
                        ('state', 'State/Province'),
                        ('postal_code', 'Postal Code'),
                        ('country', 'Country')
                    ]:
                        value = domain_info['registrant'].get(field)
                        if value:
                            f.write(f"  {label}: {value}\n")
                    
                    # If no registrant data found
                    if not any(domain_info['registrant'].values()):
                        f.write("  No registrant information available\n")
                    
                    f.write("\n")
                    
                    # Admin Information
                    f.write("Admin Information:\n")
                    
                    for field, label in [
                        ('name', 'Name'),
                        ('organization', 'Organization'),
                        ('email', 'Email'),
                        ('phone', 'Phone'),
                        ('fax', 'Fax'),
                        ('street', 'Street'),
                        ('city', 'City'),
                        ('state', 'State/Province'),
                        ('postal_code', 'Postal Code'),
                        ('country', 'Country')
                    ]:
                        value = domain_info['admin'].get(field)
                        if value:
                            f.write(f"  {label}: {value}\n")
                    
                    # If no admin data found
                    if not any(domain_info['admin'].values()):
                        f.write("  No admin information available\n")
                    
                    f.write("\n")
                    
                    # Tech Information
                    f.write("Tech Information:\n")
                    
                    for field, label in [
                        ('name', 'Name'),
                        ('organization', 'Organization'),
                        ('email', 'Email'),
                        ('phone', 'Phone'),
                        ('fax', 'Fax'),
                        ('street', 'Street'),
                        ('city', 'City'),
                        ('state', 'State/Province'),
                        ('postal_code', 'Postal Code'),
                        ('country', 'Country')
                    ]:
                        value = domain_info['tech'].get(field)
                        if value:
                            f.write(f"  {label}: {value}\n")
                    
                    # If no tech data found
                    if not any(domain_info['tech'].values()):
                        f.write("  No tech information available\n")
                    
                    f.write("\n")
                    
                    # General domain information
                    f.write("Domain Details:\n")
                    
                    # Debug info - uncomment for troubleshooting
                    # f.write(f"DEBUG - Domain fields available: {', '.join([k for k, v in domain_info.items() if v and not isinstance(v, dict)])}\n")
                    
                    if domain_info.get('registrar'):
                        f.write(f"  Registrar: {domain_info['registrar']}\n")
                    
                    if domain_info.get('creation_date'):
                        f.write(f"  Creation Date: {domain_info['creation_date']}\n")
                    
                    if domain_info.get('update_date'):
                        f.write(f"  Updated Date: {domain_info['update_date']}\n")
                    
                    if domain_info.get('expiration_date'):
                        f.write(f"  Expiration Date: {domain_info['expiration_date']}\n")
                    
                    # If no general domain details found
                    if not any(domain_info.get(field) for field in ['registrar', 'creation_date', 'update_date', 'expiration_date']):
                        f.write("  No domain details available\n")
                    
                    f.write("\n")
                    
                    # Domain Status
                    if domain_info.get('domain_status'):
                        f.write("Domain Status:\n")
                        for status in domain_info['domain_status']:
                            f.write(f"  - {status}\n")
                        f.write("\n")
                    
                    # Name Servers
                    if domain_info.get('name_servers'):
                        f.write("Name Servers:\n")
                        for ns in domain_info['name_servers']:
                            f.write(f"  - {ns}\n")
                        f.write("\n")
                    
                    # IP Address Information
                    if domain_info.get('ip_addresses'):
                        f.write("IP ADDRESS INFORMATION\n")
                        f.write("---------------------\n\n")
                        
                        for ip in domain_info['ip_addresses']:
                            f.write(f"{target_domain} -> {ip}\n")
                            
                            if ip in self.ip_info:
                                ip_data = self.ip_info[ip]
                                if ip_data.get('cidr'):
                                    f.write(f"  IP CIDR: {ip_data['cidr']}\n")
                                
                                if ip_data.get('asn'):
                                    f.write(f"  Origin AS: {ip_data['asn']}")
                                    if ip_data.get('organization'):
                                        f.write(f" ({ip_data['organization']})")
                                    f.write("\n")
                                
                                if ip_data.get('country'):
                                    f.write(f"  Country: {ip_data['country']}\n")
                                
                                if ip_data.get('reverse_dns'):
                                    f.write(f"  Reverse DNS: {ip_data['reverse_dns']}\n")
                            else:
                                f.write("  No detailed IP information available\n")
                            
                            f.write("\n")
                else:
                    f.write("DOMAIN INFORMATION\n")
                    f.write("-----------------\n\n")
                    f.write(f"Domain: {target_domain}\n\n")
                    f.write("No WHOIS information could be retrieved for this domain.\n\n")
            
            # Document Metadata
            f.write("DOCUMENT METADATA INFORMATION\n")
            f.write("---------------------------\n\n")
            
            if self.document_metadata:
                for file_path, metadata in self.document_metadata.items():
                    filename = os.path.basename(file_path)
                    file_type = os.path.splitext(filename)[1].lower().replace('.', '')
                    
                    f.write(f"File Name: {filename}\n")
                    f.write(f"File Type: {file_type}\n")
                    f.write(f"File Size: {metadata['file_size']} bytes\n")
                    
                    if metadata.get('title'):
                        f.write(f"Title: {metadata['title']}\n")
                    
                    if metadata.get('subject'):
                        f.write(f"Subject: {metadata['subject']}\n")
                    
                    if metadata.get('authors'):
                        f.write("Authors/Users:\n")
                        for author in sorted(metadata['authors']):
                            f.write(f"  - {author}\n")
                    
                    if metadata.get('creation_date'):
                        f.write(f"Creation Date: {metadata['creation_date']}\n")
                    
                    if metadata.get('modification_date'):
                        f.write(f"Modification Date: {metadata['modification_date']}\n")
                    
                    if metadata.get('software'):
                        f.write("Software Used:\n")
                        for sw in sorted(metadata['software']):
                            f.write(f"  - {sw}\n")
                    
                    if metadata.get('found_emails'):
                        f.write("Emails Found in Document:\n")
                        for email in sorted(metadata['found_emails']):
                            f.write(f"  - {email}\n")
                    
                    if metadata.get('found_urls'):
                        f.write("URLs Found in Document:\n")
                        for url in sorted(metadata['found_urls']):
                            f.write(f"  - {url}\n")
                    
                    if metadata.get('found_paths'):
                        f.write("Paths Found in Document:\n")
                        for path in sorted(metadata['found_paths']):
                            f.write(f"  - {path}\n")
                    
                    # Add GPS data if available
                    if 'gps_data' in metadata and metadata['gps_data']:
                        f.write("GPS Coordinates:\n")
                        gps_data = metadata['gps_data']
                        if 'lat' in gps_data:
                            f.write(f"  Latitude: {gps_data['lat']}\n")
                        if 'lon' in gps_data:
                            f.write(f"  Longitude: {gps_data['lon']}\n")
                        if 'alt' in gps_data:
                            f.write(f"  Altitude: {gps_data['alt']}\n")
                    
                    # Add device info if available
                    if 'device_info' in metadata and metadata['device_info']:
                        f.write("Device Information:\n")
                        device_info = metadata['device_info']
                        for key, value in device_info.items():
                            f.write(f"  {key}: {value}\n")
                    
                    # Output all metadata fields - FULL DETAILED LISTING
                    f.write("\nAll Metadata Fields:\n")
                    f.write("-" * 50 + "\n")
                    
                    if 'all_metadata' in metadata and metadata['all_metadata']:
                        # Sort keys for better readability
                        for key in sorted(metadata['all_metadata'].keys()):
                            value = metadata['all_metadata'][key]
                            if value is not None:
                                # Format the value based on its type
                                if isinstance(value, (list, dict)):
                                    formatted_value = json.dumps(value)
                                else:
                                    formatted_value = str(value)
                                f.write(f"  {key}: {formatted_value}\n")
                    elif 'exiftool_metadata' in metadata and metadata['exiftool_metadata']:
                        # Flatten the nested metadata structure for display
                        flattened = self._flatten_metadata(metadata['exiftool_metadata'])
                        for key in sorted(flattened.keys()):
                            value = flattened[key]
                            if value is not None:
                                # Format the value based on its type
                                if isinstance(value, (list, dict)):
                                    formatted_value = json.dumps(value)
                                else:
                                    formatted_value = str(value)
                                f.write(f"  {key}: {formatted_value}\n")
                    else:
                        f.write("  No detailed metadata available\n")
                    
                    f.write("\n" + "-"*50 + "\n\n")
            else:
                f.write("No document metadata found.\n\n")

    def _analyze_domain_info(self, domain):
        """Gather comprehensive information about a specific domain"""
        # Initialize structure with all fields set to None or empty lists
        domain_info = {
            'registrant': {
                'name': None,
                'organization': None,
                'email': None,
                'phone': None,
                'fax': None,
                'street': None,
                'city': None,
                'state': None,
                'postal_code': None,
                'country': None
            },
            'admin': {
                'name': None,
                'organization': None,
                'email': None,
                'phone': None,
                'fax': None,
                'street': None,
                'city': None,
                'state': None,
                'postal_code': None,
                'country': None
            },
            'tech': {
                'name': None,
                'organization': None,
                'email': None,
                'phone': None,
                'fax': None,
                'street': None,
                'city': None,
                'state': None,
                'postal_code': None,
                'country': None
            },
            'registrar': None,
            'creation_date': None,
            'update_date': None,
            'expiration_date': None,
            'name_servers': [],
            'domain_status': [],
            'ip_addresses': [],
            'mx_records': []
        }
        
        # Get WHOIS information
        try:
            logger.info(f"Getting WHOIS information for {domain}")
            w = whois.whois(domain)
            logger.debug(f"Raw WHOIS data: {w}")
            
            # Convert data to a dictionary for easier handling
            whois_dict = {}
            for key, value in w.items():
                if value is not None:
                    whois_dict[key.lower()] = value
            
            # Process standard fields
            if 'registrar' in whois_dict:
                domain_info['registrar'] = whois_dict['registrar']
            
            # Process dates
            for date_field, target_field in [
                ('creation_date', 'creation_date'),
                ('updated_date', 'update_date'),
                ('expiration_date', 'expiration_date')
            ]:
                if date_field in whois_dict:
                    value = whois_dict[date_field]
                    if isinstance(value, list) and len(value) > 0:
                        domain_info[target_field] = value[0]
                    else:
                        domain_info[target_field] = value
            
            # Process name servers
            if 'name_servers' in whois_dict:
                ns_list = whois_dict['name_servers']
                if isinstance(ns_list, list):
                    domain_info['name_servers'] = ns_list
                elif ns_list:
                    domain_info['name_servers'] = [ns_list]
            
            # Process domain status
            if 'status' in whois_dict:
                status_list = whois_dict['status']
                if isinstance(status_list, list):
                    domain_info['domain_status'] = status_list
                elif status_list:
                    domain_info['domain_status'] = [status_list]
            
            # Process contact information
            contact_types = ['registrant', 'admin', 'tech']
            contact_fields = ['name', 'organization', 'email', 'phone', 'fax', 
                              'street', 'city', 'state', 'postal_code', 'country']
            
            for contact_type in contact_types:
                for field in contact_fields:
                    key = f"{contact_type}_{field}"
                    if key in whois_dict:
                        domain_info[contact_type][field] = whois_dict[key]
            
            # Special handling for emails (might be in a separate field)
            if 'emails' in whois_dict and whois_dict['emails']:
                emails = whois_dict['emails']
                emails_list = emails if isinstance(emails, list) else [emails]
                
                if emails_list and len(emails_list) > 0:
                    # Assign emails to contacts if not already set
                    if not domain_info['registrant']['email'] and len(emails_list) > 0:
                        domain_info['registrant']['email'] = emails_list[0]
                    if not domain_info['admin']['email'] and len(emails_list) > 1:
                        domain_info['admin']['email'] = emails_list[1]
                    if not domain_info['tech']['email'] and len(emails_list) > 2:
                        domain_info['tech']['email'] = emails_list[2]
            
            # Process raw text data using regex if available
            if hasattr(w, 'text') and w.text:
                whois_text = w.text.lower()
                logger.debug(f"Processing raw WHOIS text: {whois_text[:200]}...")  # Log first 200 chars
                
                # Process contact information using regex
                for contact_type in contact_types:
                    for field in contact_fields:
                        # Only try to extract data if it's not already set
                        if not domain_info[contact_type][field]:
                            pattern = rf"{contact_type}\s+{field}:\s*([^\n]+)"
                            match = re.search(pattern, whois_text)
                            if match:
                                domain_info[contact_type][field] = match.group(1).strip()
                
                # Try to extract registrar info if not already set
                if not domain_info['registrar']:
                    registrar_match = re.search(r"registrar:\s*([^\n]+)", whois_text)
                    if registrar_match:
                        domain_info['registrar'] = registrar_match.group(1).strip()
                
                # Try to extract name servers if not already set
                if not domain_info['name_servers']:
                    ns_matches = re.findall(r"name server:\s*([^\n]+)", whois_text)
                    if ns_matches:
                        domain_info['name_servers'] = [ns.strip() for ns in ns_matches]
        except Exception as e:
            logger.error(f"Error getting WHOIS information for {domain}: {str(e)}")
            # Print traceback for debugging
            import traceback
            logger.error(traceback.format_exc())
        
        # Get DNS A records
        try:
            logger.info(f"Getting DNS A records for {domain}")
            # First try to get all A records
            answers = dns.resolver.resolve(domain, 'A')
            for answer in answers:
                ip = answer.to_text()
                domain_info['ip_addresses'].append(ip)
                
                # Get additional IP information
                self._get_ip_info(ip, domain)
            
            # Also check www. subdomain
            try:
                www_domain = f"www.{domain}"
                www_answers = dns.resolver.resolve(www_domain, 'A')
                for answer in www_answers:
                    ip = answer.to_text()
                    if ip not in domain_info['ip_addresses']:
                        domain_info['ip_addresses'].append(ip)
                        self._get_ip_info(ip, domain)
            except Exception as www_e:
                logger.debug(f"Error resolving www.{domain}: {str(www_e)}")
        except Exception as dns_e:
            logger.error(f"Error resolving DNS A records for {domain}: {str(dns_e)}")
        
        # Get MX records
        try:
            logger.info(f"Getting DNS MX records for {domain}")
            mx_records = dns.resolver.resolve(domain, 'MX')
            for mx in mx_records:
                domain_info['mx_records'].append(f"{mx.preference} {mx.exchange}")
        except Exception as mx_e:
            logger.debug(f"Error resolving MX records for {domain}: {str(mx_e)}")
        
        # Log the collected information
        logger.info(f"Completed domain info collection for {domain}")
        
        return domain_info

    def _map_contact_attribute(self, contact_dict, attr_name, attr_value):
        """Map WHOIS attributes to contact fields"""
        attr_lower = attr_name.lower()
        
        # Process name fields
        if any(name_field in attr_lower for name_field in ['name', 'registrant', 'admin', 'tech']):
            if 'name' in attr_lower or attr_lower in ['registrant', 'admin', 'tech']:
                contact_dict['name'] = attr_value
        
        # Process organization fields
        elif any(org_field in attr_lower for org_field in ['organization', 'org', 'company']):
            contact_dict['organization'] = attr_value
        
        # Process email fields
        elif 'email' in attr_lower:
            contact_dict['email'] = attr_value
        
        # Process phone fields
        elif 'phone' in attr_lower:
            contact_dict['phone'] = attr_value
        
        # Process address fields
        elif any(addr_field in attr_lower for addr_field in ['address', 'street', 'city', 'state', 'country']):
            if contact_dict['address']:
                contact_dict['address'] = f"{contact_dict['address']}, {attr_value}"
            else:
                contact_dict['address'] = attr_value

    def _get_ip_info(self, ip, associated_domain=None):
        """Get detailed information about an IP address"""
        if ip in self.ip_info:
            return self.ip_info[ip]
            
        ip_data = {
            'cidr': None,
            'asn': None,
            'organization': None,
            'country': None,
            'associated_domains': set(),
            'reverse_dns': None
        }
        
        if associated_domain:
            ip_data['associated_domains'].add(associated_domain)
        
        # Try to get WHOIS information for the IP
        try:
            ip_whois = IPWhois(ip)
            results = ip_whois.lookup_rdap()
            
            if results:
                if 'network' in results and 'cidr' in results['network']:
                    ip_data['cidr'] = results['network']['cidr']
                
                if 'asn' in results:
                    ip_data['asn'] = results['asn']
                    
                if 'asn_description' in results:
                    ip_data['organization'] = results['asn_description']
                    
                if 'network' in results and 'country' in results['network']:
                    ip_data['country'] = results['network']['country']
        except Exception as e:
            logger.warning(f"Error getting WHOIS information for IP {ip}: {str(e)}")
        
        # Try reverse DNS lookup
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            ip_data['reverse_dns'] = hostname
        except:
            pass
        
        self.ip_info[ip] = ip_data
        return ip_data

    def _generate_html_report(self, report_path, target_domain):
        """Generate a detailed HTML report"""
        with open(report_path, 'w') as f:
            # HTML header
            f.write("""<!DOCTYPE html>
    <html>
    <head>
        <title>Sidikjari Metadata Analysis Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1 { color: #2c3e50; }
            h2 { color: #3498db; margin-top: 30px; }
            h3 { color: #2980b9; }
            .container { max-width: 1200px; margin: 0 auto; }
            .section { margin-bottom: 30px; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
            .metadata-item { margin-bottom: 20px; padding: 10px; background-color: #f9f9f9; border-radius: 5px; }
            table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
            th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
            th { background-color: #f2f2f2; }
            .footer { margin-top: 50px; text-align: center; font-size: 12px; color: #7f8c8d; }
            .metadata-table { font-size: 12px; }
            .key-column { width: 40%; font-weight: bold; }
            .value-column { width: 60%; word-break: break-word; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Sidikjari Metadata Analysis Report</h1>
    """)
    
            # Target information
            f.write(f"<p><strong>Target:</strong> {self.target_url if self.target_url else self.input_dir}</p>")
            
            # Domain Information section
            if target_domain:
                # Try to get domain information
                domain_info = self._analyze_domain_info(target_domain)
                
                if domain_info:
                    f.write("<div class='section'>")
                    f.write("<h2>DOMAIN INFORMATION</h2>")
                    f.write(f"<p><strong>Domain:</strong> {target_domain}</p>")
                    
                    # Registrant Information
                    f.write("<h3>Registrant Information</h3>")
                    f.write("<table>")
                    if domain_info['registrant']['name']:
                        f.write(f"<tr><td>Name</td><td>{domain_info['registrant']['name']}</td></tr>")
                    if domain_info['registrant']['organization']:
                        f.write(f"<tr><td>Organization</td><td>{domain_info['registrant']['organization']}</td></tr>")
                    if domain_info['registrant']['email']:
                        f.write(f"<tr><td>Email</td><td>{domain_info['registrant']['email']}</td></tr>")
                    if domain_info['registrant']['phone']:
                        f.write(f"<tr><td>Phone</td><td>{domain_info['registrant']['phone']}</td></tr>")
                    if domain_info['registrant']['fax']:
                        f.write(f"<tr><td>Fax</td><td>{domain_info['registrant']['fax']}</td></tr>")
                    if domain_info['registrant']['street']:
                        f.write(f"<tr><td>Street</td><td>{domain_info['registrant']['street']}</td></tr>")
                    if domain_info['registrant']['city']:
                        f.write(f"<tr><td>City</td><td>{domain_info['registrant']['city']}</td></tr>")
                    if domain_info['registrant']['state']:
                        f.write(f"<tr><td>State/Province</td><td>{domain_info['registrant']['state']}</td></tr>")
                    if domain_info['registrant']['postal_code']:
                        f.write(f"<tr><td>Postal Code</td><td>{domain_info['registrant']['postal_code']}</td></tr>")
                    if domain_info['registrant']['country']:
                        f.write(f"<tr><td>Country</td><td>{domain_info['registrant']['country']}</td></tr>")
                    
                    # If no registrant data was found, display a message
                    if not any([domain_info['registrant'][field] for field in domain_info['registrant']]):
                        f.write("<tr><td colspan='2'>No registrant information available</td></tr>")
                    
                    f.write("</table>")
                    
                    # Admin Information
                    f.write("<h3>Admin Information</h3>")
                    f.write("<table>")
                    if domain_info['admin']['name']:
                        f.write(f"<tr><td>Name</td><td>{domain_info['admin']['name']}</td></tr>")
                    if domain_info['admin']['organization']:
                        f.write(f"<tr><td>Organization</td><td>{domain_info['admin']['organization']}</td></tr>")
                    if domain_info['admin']['email']:
                        f.write(f"<tr><td>Email</td><td>{domain_info['admin']['email']}</td></tr>")
                    if domain_info['admin']['phone']:
                        f.write(f"<tr><td>Phone</td><td>{domain_info['admin']['phone']}</td></tr>")
                    if domain_info['admin']['fax']:
                        f.write(f"<tr><td>Fax</td><td>{domain_info['admin']['fax']}</td></tr>")
                    if domain_info['admin']['street']:
                        f.write(f"<tr><td>Street</td><td>{domain_info['admin']['street']}</td></tr>")
                    if domain_info['admin']['city']:
                        f.write(f"<tr><td>City</td><td>{domain_info['admin']['city']}</td></tr>")
                    if domain_info['admin']['state']:
                        f.write(f"<tr><td>State/Province</td><td>{domain_info['admin']['state']}</td></tr>")
                    if domain_info['admin']['postal_code']:
                        f.write(f"<tr><td>Postal Code</td><td>{domain_info['admin']['postal_code']}</td></tr>")
                    if domain_info['admin']['country']:
                        f.write(f"<tr><td>Country</td><td>{domain_info['admin']['country']}</td></tr>")
                    
                    # If no admin data was found, display a message
                    if not any([domain_info['admin'][field] for field in domain_info['admin']]):
                        f.write("<tr><td colspan='2'>No admin information available</td></tr>")
                    
                    f.write("</table>")
                    
                    # Tech Information
                    f.write("<h3>Tech Information</h3>")
                    f.write("<table>")
                    if domain_info['tech']['name']:
                        f.write(f"<tr><td>Name</td><td>{domain_info['tech']['name']}</td></tr>")
                    if domain_info['tech']['organization']:
                        f.write(f"<tr><td>Organization</td><td>{domain_info['tech']['organization']}</td></tr>")
                    if domain_info['tech']['email']:
                        f.write(f"<tr><td>Email</td><td>{domain_info['tech']['email']}</td></tr>")
                    if domain_info['tech']['phone']:
                        f.write(f"<tr><td>Phone</td><td>{domain_info['tech']['phone']}</td></tr>")
                    if domain_info['tech']['fax']:
                        f.write(f"<tr><td>Fax</td><td>{domain_info['tech']['fax']}</td></tr>")
                    if domain_info['tech']['street']:
                        f.write(f"<tr><td>Street</td><td>{domain_info['tech']['street']}</td></tr>")
                    if domain_info['tech']['city']:
                        f.write(f"<tr><td>City</td><td>{domain_info['tech']['city']}</td></tr>")
                    if domain_info['tech']['state']:
                        f.write(f"<tr><td>State/Province</td><td>{domain_info['tech']['state']}</td></tr>")
                    if domain_info['tech']['postal_code']:
                        f.write(f"<tr><td>Postal Code</td><td>{domain_info['tech']['postal_code']}</td></tr>")
                    if domain_info['tech']['country']:
                        f.write(f"<tr><td>Country</td><td>{domain_info['tech']['country']}</td></tr>")
                    
                    # If no tech data was found, display a message
                    if not any([domain_info['tech'][field] for field in domain_info['tech']]):
                        f.write("<tr><td colspan='2'>No tech information available</td></tr>")
                    
                    f.write("</table>")
                    
                    # General domain information
                    f.write("<h3>Domain Details</h3>")
                    f.write("<table>")
                    if domain_info['registrar']:
                        f.write(f"<tr><td>Registrar</td><td>{domain_info['registrar']}</td></tr>")
                    if domain_info['creation_date']:
                        f.write(f"<tr><td>Creation Date</td><td>{domain_info['creation_date']}</td></tr>")
                    if domain_info['update_date']:
                        f.write(f"<tr><td>Updated Date</td><td>{domain_info['update_date']}</td></tr>")
                    if domain_info['expiration_date']:
                        f.write(f"<tr><td>Expiration Date</td><td>{domain_info['expiration_date']}</td></tr>")
                    
                    # If no domain details were found, display a message
                    if not any([domain_info[field] for field in ['registrar', 'creation_date', 'update_date', 'expiration_date']]):
                        f.write("<tr><td colspan='2'>No domain details available</td></tr>")
                    
                    f.write("</table>")
                    
                    if domain_info['domain_status']:
                        f.write("<h3>Domain Status</h3>")
                        f.write("<ul>")
                        for status in domain_info['domain_status']:
                            f.write(f"<li>{status}</li>")
                        f.write("</ul>")
                    
                    if domain_info['name_servers']:
                        f.write("<h3>Name Servers</h3>")
                        f.write("<ul>")
                        for ns in domain_info['name_servers']:
                            f.write(f"<li>{ns}</li>")
                        f.write("</ul>")
                    
                    f.write("</div>")
                    
                    # IP Address Information
                    if domain_info['ip_addresses']:
                        f.write("<div class='section'>")
                        f.write("<h2>IP ADDRESS INFORMATION</h2>")
                        
                        for ip in domain_info['ip_addresses']:
                            f.write(f"<h3>{target_domain} -> {ip}</h3>")
                            
                            f.write("<table>")
                            if ip in self.ip_info:
                                ip_data = self.ip_info[ip]
                                if ip_data['cidr']:
                                    f.write(f"<tr><td>IP CIDR</td><td>{ip_data['cidr']}</td></tr>")
                                
                                if ip_data['asn']:
                                    asn_info = f"{ip_data['asn']}"
                                    if ip_data['organization']:
                                        asn_info += f" ({ip_data['organization']})"
                                    f.write(f"<tr><td>Origin AS</td><td>{asn_info}</td></tr>")
                                
                                if ip_data['country']:
                                    f.write(f"<tr><td>Country</td><td>{ip_data['country']}</td></tr>")
                                
                                if ip_data['reverse_dns']:
                                    f.write(f"<tr><td>Reverse DNS</td><td>{ip_data['reverse_dns']}</td></tr>")
                            else:
                                f.write("<tr><td colspan='2'>No detailed IP information available</td></tr>")
                            f.write("</table>")
                        
                        f.write("</div>")
    
            # Continue with the rest of the report...
            # Document Metadata Section and other sections
            # ...
    
            # Footer
            f.write("""
            <div class="footer">
                <p>Report generated by Sidikjari - Metadata Extraction Tool</p>
                <p>Red Cell Security, LLC - www.redcellsecurity.org</p>
            </div>
        </div>
    </body>
    </html>""")

    def run(self):
        """Execute the full analysis"""
        logger.info(f"{Fore.GREEN}Starting Sidikjari analysis on {self.target_url}{Style.RESET_ALL}")
        
        # Step 1: Crawl website
        self.crawl_website()
        
        # Step 2: Download documents
        self.download_documents()
        
        # Step 3: Extract metadata
        self.extract_all_metadata()
        
        # Step 4: Generate the report
        report_path = self.generate_reports()
        
        logger.info(f"{Fore.GREEN}Analysis complete! Report available at: {report_path}{Style.RESET_ALL}")
        self._print_summary()
    
    def _print_summary(self):
        """Print a summary of the findings"""
        # Make sure to use Rich's Table class, not ReportLab's
        from rich.table import Table as RichTable
        
        table = RichTable(title="Sidikjari Analysis Summary")
        table.add_column("Item")
        table.add_column("Count")
        
        table.add_row("Documents Analyzed", str(len(self.file_paths)))
        table.add_row("Users/Authors Discovered", str(len(self.users)))
        table.add_row("Email Addresses Discovered", str(len(self.emails)))
        table.add_row("Software Identified", str(len(self.software)))
        table.add_row("Domains Discovered", str(len(self.internal_domains)))
        table.add_row("IP Addresses Found", str(len(self.ip_addresses)))
        
        console.print(table)

def main():
    parser = argparse.ArgumentParser(description="Sidikjari - Metadata extraction and analysis tool")
    parser.add_argument("--url", "-u", help="Target URL to scan")
    parser.add_argument("--output", "-o", default="output", help="Output directory")
    parser.add_argument("--depth", "-d", type=int, default=2, 
                       help="Crawl depth (0=homepage only, 1=direct links, 2=links from direct links, etc.). Higher values crawl more of the site but take longer.")
    parser.add_argument("--threads", "-t", type=int, default=10, help="Number of threads")
    parser.add_argument("--local", "-l", help="Local directory of files to analyze (instead of URL)")
    parser.add_argument("--format", "-f", default="text", 
                       help="Report format(s): 'text', 'html', 'pdf', comma-separated list, or 'all'")
    parser.add_argument("--time-delay", type=float, default=0.0,
                       help="Delay in seconds between web requests to avoid overwhelming the server (e.g., 0.5)")
    parser.add_argument("--user-agent", choices=["default", "chrome", "firefox", "safari", "edge", "mobile", "random"],
                       default="default", help="User agent to use for web requests")
    
    args = parser.parse_args()
    
    # Create output directory before setting up logging
    output_dir = args.output
    os.makedirs(output_dir, exist_ok=True)
    
    # Reconfigure logging to use the output directory
    log_path = os.path.join(output_dir, "Sidikjari.log")
    
    # Clear existing handlers and add new ones
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_path),
            logging.StreamHandler()
        ]
    )
    
    logger = logging.getLogger("Sidikjari")
    
    # Print banner
    print(f"""{Fore.CYAN}
    ████████████████████████
    █                                           █
    █              SIDIKJARI                    █
    █                                           █
    █  Metadata extraction and analysis tool    █
    █                                           █
    ████████████████████████
    {Style.RESET_ALL}""")
    
    if not args.url and not args.local:
        parser.print_help()
        print(f"\n{Fore.RED}Error: You must provide either a URL to scan or a local directory{Style.RESET_ALL}")
        sys.exit(1)
    
    # Check for required dependencies
    if not shutil.which('exiftool'):
        print(f"\n{Fore.RED}Error: ExifTool is required but not found in PATH. Please install ExifTool.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Installation instructions: https://exiftool.org/install.html{Style.RESET_ALL}")
        sys.exit(1)
    
    try:
        # Parse format option
        formats_to_generate = []
        if args.format.lower() == 'all':
            formats_to_generate = ["text", "html", "pdf"]
        else:
            # Split by comma and strip whitespace
            formats = [fmt.strip().lower() for fmt in args.format.split(',')]
            
            # Validate formats
            valid_formats = ["text", "html", "pdf"]
            for fmt in formats:
                if fmt in valid_formats:
                    formats_to_generate.append(fmt)
                else:
                    logger.warning(f"Ignoring invalid format: {fmt}. Valid formats are: {', '.join(valid_formats)}")
            
            # If no valid formats specified, default to text
            if not formats_to_generate:
                logger.warning("No valid formats specified, defaulting to text format")
                formats_to_generate = ["text"]
        
        primary_format = formats_to_generate[0]
        
        if args.url:
            # URL-based scanning - create a single instance and run once
            target_url = args.url
            if not target_url.startswith(('http://', 'https://')):
                target_url = f'https://{target_url}'
                
            sidikjari_scanner = Sidikjari(
                target_url=target_url,
                output_dir=args.output,
                depth=args.depth,
                threads=args.threads,
                report_format=primary_format,
                time_delay=args.time_delay,
                user_agent=args.user_agent
            )
            
            # Store all report formats
            sidikjari_scanner.report_formats = formats_to_generate
            
            # Run the full analysis once
            sidikjari_scanner.run()
            
        else:
            # Local directory scanning - create a single instance and run once
            print(f"{Fore.GREEN}Analyzing local directory: {args.local}{Style.RESET_ALL}")

            local_sidikjari = LocalSidikjari(
                input_dir=args.local,
                output_dir=args.output,
                threads=args.threads,
                report_format=primary_format
            )
            
            # Store all report formats
            local_sidikjari.report_formats = formats_to_generate
            
            # Run the full analysis once
            local_sidikjari.run()
            
    except Exception as e:
        logger.error(f"Error during execution: {str(e)}")
        print(f"\n{Fore.RED}An error occurred: {str(e)}{Style.RESET_ALL}")
        # Print traceback for debugging
        import traceback
        traceback.print_exc()
        sys.exit(1)

class LocalSidikjari(Sidikjari):
    """Version of Sidikjari that works with local files instead of crawling websites"""
    
    def __init__(self, input_dir, output_dir="output", threads=10, report_format="text"):
        super().__init__(target_url=None, output_dir=output_dir, threads=threads, report_format=report_format)
        self.input_dir = input_dir
    
    def crawl_website(self):
        """Find local files instead of crawling websites"""
        logger.info(f"{Fore.GREEN}Scanning directory: {self.input_dir}{Style.RESET_ALL}")
        self._find_local_documents()
    
    def download_documents(self):
        """No need to download documents as they're already local"""
        logger.info(f"{Fore.GREEN}Found {len(self.file_paths)} local documents to analyze{Style.RESET_ALL}")
        
    def _find_local_documents(self):
        """Find all documents in the input directory"""
        for root, _, files in os.walk(self.input_dir):
            for file in files:
                file_path = os.path.join(root, file)
                file_ext = os.path.splitext(file)[1].lower().replace('.', '')
                
                if file_ext in self.interesting_extensions:
                    self.file_paths.add(file_path)
                    logger.info(f"Found document to analyze: {file_path} ({file_ext})")
        
        logger.info(f"{Fore.GREEN}Found {len(self.file_paths)} documents{Style.RESET_ALL}")

if __name__ == "__main__":
    main()