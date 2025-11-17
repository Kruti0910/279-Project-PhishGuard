#!/usr/bin/env python3
"""
Email Header Analyzer Module

This module processes email files and extracts header metadata for security analysis.
It supports multiple email formats including .eml, .msg, and plain text files.
"""

import email
import os
import re
from email import policy
from email.parser import BytesParser, Parser
from email.utils import parseaddr, parsedate_to_datetime
from typing import Dict, List, Optional, Union, Tuple, Any
import logging
from datetime import datetime

# Try to import optional dependencies
try:
    import mailparser
    MAILPARSER_AVAILABLE = True
except ImportError:
    MAILPARSER_AVAILABLE = False

logger = logging.getLogger(__name__)


class EmailHeaderAnalyzer:
    """Class for processing email files and extracting header metadata for analysis."""
    
    def __init__(self, file_path: str):
        """
        Initialize the EmailHeaderAnalyzer with a file path.
        
        Args:
            file_path: Path to the email file to be analyzed
        """
        self.file_path = file_path
        self.parsed_content = None
        self.headers = {}
        self.received_headers = []
        self.body = ""
        self.body_html = ""
        self.body_plain = ""
        self.attachments = []
        
    def process_email(self) -> Dict:
        """
        Process the email file and extract header metadata for security evaluation.
        
        Returns:
            Dictionary containing processed email content with headers and metadata
        """
        if not os.path.exists(self.file_path):
            logger.error(f"File not found: {self.file_path}")
            return {}
        
        file_ext = os.path.splitext(self.file_path)[1].lower()
        
        try:
            # Select appropriate processing method based on file extension
            if file_ext == ".eml":
                self._parse_eml()
            elif file_ext == ".msg" and MAILPARSER_AVAILABLE:
                self._parse_msg()
            else:  # Process as plain text
                self._parse_text()
                
            # Analyze received headers for routing information
            self._process_received_headers()
            
            # Construct the result dictionary with extracted information
            self.parsed_content = {
                "headers": self.headers,
                "received_chain": self.received_headers,
                "body": self.body,
                "body_html": self.body_html,
                "body_plain": self.body_plain,
                "attachments": self.attachments,
                "file_path": self.file_path,
                "parse_time": datetime.now().isoformat()
            }
            
            return self.parsed_content
            
        except Exception as e:
            logger.error(f"Error processing email {self.file_path}: {str(e)}")
            return {}
    
    def _parse_eml(self) -> None:
        """
        Process an EML format email file and extract header information.
        """
        with open(self.file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        
        # Extract headers
        for name, value in msg.items():
            self.headers[name.lower()] = value
        
        # Extract body (both plain text and HTML)
        self.body_html = ""
        self.body_plain = ""
        
        if msg.is_multipart():
            for part in msg.iter_parts():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    self.body_plain += part.get_content()
                elif content_type == "text/html":
                    self.body_html += part.get_content()
                elif content_type.startswith("text/"):
                    # Fallback for other text types
                    if not self.body_plain and not self.body_html:
                        self.body += part.get_content()
                # Handle attachments
                filename = part.get_filename()
                if filename:
                    self.attachments.append({
                        "filename": filename,
                        "content_type": content_type,
                        "size": len(part.get_content())
                    })
        else:
            content_type = msg.get_content_type()
            content = msg.get_content()
            if content_type == "text/html":
                self.body_html = content
            elif content_type == "text/plain":
                self.body_plain = content
            else:
                self.body = content
        
        # Set primary body content (prefer plain text, fallback to HTML, then generic)
        if self.body_plain:
            self.body = self.body_plain
        elif self.body_html:
            self.body = self.body_html
    
    def _parse_msg(self) -> None:
        """
        Process an MSG format email file using the mailparser library.
        Requires the mailparser package to be installed.
        """
        if not MAILPARSER_AVAILABLE:
            raise ImportError("mailparser library is required for MSG files")
        
        mail = mailparser.parse_from_file(self.file_path)
        
        # Extract headers
        for name, value in mail.headers.items():
            self.headers[name.lower()] = value
        
        # Extract body
        if mail.text_plain:
            self.body_plain = "\n".join(mail.text_plain)
        if mail.text_html:
            self.body_html = "\n".join(mail.text_html)
        
        # Set primary body content (prefer plain text)
        if self.body_plain:
            self.body = self.body_plain
        elif self.body_html:
            self.body = self.body_html
        
        # Extract attachments
        for attachment in mail.attachments:
            self.attachments.append({
                "filename": attachment.get("filename", "unknown"),
                "content_type": attachment.get("mail_content_type", "unknown"),
                "size": len(attachment.get("payload", ""))
            })
    
    def _parse_text(self) -> None:
        """
        Process a plain text email file and extract header information.
        """
        with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Split headers and body
        parts = re.split(r'\n\s*\n', content, 1)
        
        if len(parts) > 1:
            header_text, self.body = parts
        else:
            header_text = parts[0]
            self.body = ""
        
        # Parse headers
        header_lines = header_text.split('\n')
        current_header = None
        current_value = ""
        
        for line in header_lines:
            # New header
            if re.match(r'^[A-Za-z\-]+:', line):
                # Save previous header if exists
                if current_header:
                    self.headers[current_header.lower()] = current_value.strip()
                
                # Start new header
                parts = line.split(':', 1)
                current_header = parts[0].strip()
                current_value = parts[1].strip() if len(parts) > 1 else ""
            # Continuation of previous header
            elif current_header and line.startswith(' '):
                current_value += " " + line.strip()
        
        # Save the last header
        if current_header:
            self.headers[current_header.lower()] = current_value.strip()
    
    def _process_received_headers(self) -> None:
        """
        Analyze and extract routing information from Received headers in the email.
        """
        # Get all Received headers
        received_headers = []
        
        # Check for single Received header
        if "received" in self.headers:
            received_headers.append(self.headers["received"])
        
        # Check for multiple Received headers in raw format
        for key in self.headers.keys():
            if key.startswith("received") and key != "received":
                received_headers.append(self.headers[key])
        
        # Parse each Received header
        for i, header in enumerate(received_headers):
            parsed = self._parse_received_header(header)
            parsed["position"] = i  # Add position in chain
            self.received_headers.append(parsed)
        
        # Sort by position (most recent first is standard in email headers)
        self.received_headers.sort(key=lambda x: x["position"])
    
    def _parse_received_header(self, header: str) -> Dict:
        """
        Extract routing details from a single Received header line.
        
        Args:
            header: The raw Received header string to analyze
            
        Returns:
            Dictionary containing extracted routing components
        """
        result = {
            "raw": header,
            "from": None,
            "by": None,
            "with": None,
            "for": None,
            "date": None,
            "ip": None
        }
        
        # Extract from
        from_match = re.search(r'from\s+([^\s;]+)', header)
        if from_match:
            result["from"] = from_match.group(1)
        
        # Extract by
        by_match = re.search(r'by\s+([^\s;]+)', header)
        if by_match:
            result["by"] = by_match.group(1)
        
        # Extract with protocol
        with_match = re.search(r'with\s+([^\s;]+)', header)
        if with_match:
            result["with"] = with_match.group(1)
        
        # Extract for recipient
        for_match = re.search(r'for\s+([^\s;]+)', header)
        if for_match:
            result["for"] = for_match.group(1)
        
        # Extract date
        date_match = re.search(r';\s*(.+)$', header)
        if date_match:
            date_str = date_match.group(1).strip()
            try:
                result["date"] = parsedate_to_datetime(date_str).isoformat()
            except Exception:
                result["date"] = date_str
        
        # Extract IP addresses
        ip_matches = re.findall(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', header)
        if ip_matches:
            result["ip"] = ip_matches[0]  # Take the first IP found
        
        return result
    
    def get_header(self, name: str, default: Any = None) -> Any:
        """
        Retrieve a specific header field value from the processed email.
        
        Args:
            name: Header field name (case-insensitive lookup)
            default: Default value to return if header not found
            
        Returns:
            Header field value or the provided default value
        """
        return self.headers.get(name.lower(), default)
    
    def get_sender_info(self) -> Dict:
        """
        Extract and process sender address information from email headers.
        
        Returns:
            Dictionary containing sender name, email address, and domain
        """
        from_header = self.get_header("from", "")
        name, email_addr = parseaddr(from_header)
        
        domain = ""
        if email_addr and "@" in email_addr:
            domain = email_addr.split("@", 1)[1]
        
        return {
            "name": name,
            "email": email_addr,
            "domain": domain,
            "raw": from_header
        }
    
    def get_recipient_info(self) -> Dict:
        """
        Extract and organize recipient address information from email headers.
        
        Returns:
            Dictionary containing To, Cc, and Bcc recipient lists
        """
        result = {
            "to": [],
            "cc": [],
            "bcc": []
        }
        
        # Process To header
        to_header = self.get_header("to", "")
        if to_header:
            for addr in to_header.split(","):
                name, email_addr = parseaddr(addr.strip())
                if email_addr:
                    result["to"].append({
                        "name": name,
                        "email": email_addr
                    })
        
        # Process Cc header
        cc_header = self.get_header("cc", "")
        if cc_header:
            for addr in cc_header.split(","):
                name, email_addr = parseaddr(addr.strip())
                if email_addr:
                    result["cc"].append({
                        "name": name,
                        "email": email_addr
                    })
        
        # Process Bcc header (rarely present in received emails)
        bcc_header = self.get_header("bcc", "")
        if bcc_header:
            for addr in bcc_header.split(","):
                name, email_addr = parseaddr(addr.strip())
                if email_addr:
                    result["bcc"].append({
                        "name": name,
                        "email": email_addr
                    })
        
        return result


if __name__ == "__main__":
    # Test script when executed directly
    import sys
    if len(sys.argv) > 1:
        analyzer = EmailHeaderAnalyzer(sys.argv[1])
        content = analyzer.process_email()
        print(f"Processed email: {sys.argv[1]}")
        print(f"From: {analyzer.get_sender_info()}")
        print(f"Subject: {analyzer.get_header('subject')}")
        print(f"Date: {analyzer.get_header('date')}")
        print(f"Received chain length: {len(analyzer.received_headers)}")
    else:
        print("Please provide an email file path as argument")

