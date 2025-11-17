#!/usr/bin/env python3
"""
Email Attribute Extractor Module

This module collects and extracts attributes from email headers for security evaluation.
It examines various header fields to identify suspicious patterns and security indicators.
"""

import re
import socket
from datetime import datetime, timedelta
from email.utils import parseaddr, parsedate_to_datetime
from typing import Dict, List, Optional, Union, Tuple, Any
from urllib.parse import urlparse
import logging

# Try to import optional dependencies
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

logger = logging.getLogger(__name__)

# Common free email providers
FREE_EMAIL_PROVIDERS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "mail.com", "protonmail.com", "icloud.com", "zoho.com", "yandex.com",
    "gmx.com", "tutanota.com", "mail.ru", "inbox.com", "live.com"
]


class EmailAttributeExtractor:
    """Class for collecting and extracting attributes from email headers for security assessment."""
    
    def __init__(self, parsed_content: Dict):
        """
        Initialize the EmailAttributeExtractor with processed email content.
        
        Args:
            parsed_content: Dictionary containing processed email data
        """
        self.parsed_content = parsed_content
        self.headers = parsed_content.get("headers", {})
        self.received_chain = parsed_content.get("received_chain", [])
        self.extracted_attributes = {}
    
    def collect_header_attributes(self) -> Dict:
        """
        Collect all relevant attributes from the email headers for security analysis.
        
        Returns:
            Dictionary containing all extracted header attributes
        """
        # Basic header features
        self.extract_sender_features()
        self.extract_recipient_features()
        self.extract_subject_features()
        self.extract_date_features()
        
        # Advanced header features
        self.extract_received_chain_features()
        self.extract_authentication_features()
        self.extract_content_features()
        self.extract_message_id_features()
        
        # Include raw headers for reference
        self.extracted_attributes["raw_headers"] = self.headers
        
        return self.extracted_attributes
    
    def extract_sender_features(self) -> None:
        """
        Extract features related to the sender of the email.
        """
        sender_features = {}
        
        # Get From header
        from_header = self.headers.get("from", "")
        sender_name, sender_email = parseaddr(from_header)
        
        # Get Reply-To header
        reply_to_header = self.headers.get("reply-to", "")
        reply_to_name, reply_to_email = parseaddr(reply_to_header)
        
        # Get Return-Path header
        return_path_header = self.headers.get("return-path", "")
        _, return_path_email = parseaddr(return_path_header)
        
        # Extract domains
        sender_domain = self._extract_domain(sender_email)
        reply_to_domain = self._extract_domain(reply_to_email)
        return_path_domain = self._extract_domain(return_path_email)
        
        # Check for mismatches
        domain_mismatch = False
        email_mismatch = False
        
        if sender_email and reply_to_email and sender_email != reply_to_email:
            email_mismatch = True
        
        if sender_domain and reply_to_domain and sender_domain != reply_to_domain:
            domain_mismatch = True
        
        # Check for free email providers
        is_free_provider = any(domain in FREE_EMAIL_PROVIDERS for domain in 
                              [sender_domain, reply_to_domain, return_path_domain] 
                              if domain)
        
        # Check for display name spoofing
        display_name_contains_email = False
        if sender_name and "@" in sender_name:
            display_name_contains_email = True
        
        # Store features
        sender_features["from_email"] = sender_email
        sender_features["from_name"] = sender_name
        sender_features["from_domain"] = sender_domain
        sender_features["reply_to_email"] = reply_to_email
        sender_features["reply_to_domain"] = reply_to_domain
        sender_features["return_path_email"] = return_path_email
        sender_features["return_path_domain"] = return_path_domain
        sender_features["email_mismatch"] = email_mismatch
        sender_features["domain_mismatch"] = domain_mismatch
        sender_features["is_free_provider"] = is_free_provider
        sender_features["display_name_contains_email"] = display_name_contains_email
        
        # Check for domain age and reputation if DNS is available
        if DNS_AVAILABLE and sender_domain:
            sender_features["domain_has_mx"] = self._check_domain_has_mx(sender_domain)
            sender_features["domain_has_spf"] = self._check_domain_has_spf(sender_domain)
            sender_features["domain_has_dmarc"] = self._check_domain_has_dmarc(sender_domain)
        
        self.extracted_attributes["sender"] = sender_features
    
    def extract_recipient_features(self) -> None:
        """
        Extract features related to the recipients of the email.
        """
        recipient_features = {}
        
        # Get To header
        to_header = self.headers.get("to", "")
        to_recipients = []
        
        if to_header:
            # Handle multiple recipients
            for addr in to_header.split(","):
                name, email = parseaddr(addr.strip())
                if email:
                    to_recipients.append({"name": name, "email": email})
        
        # Get Cc header
        cc_header = self.headers.get("cc", "")
        cc_recipients = []
        
        if cc_header:
            for addr in cc_header.split(","):
                name, email = parseaddr(addr.strip())
                if email:
                    cc_recipients.append({"name": name, "email": email})
        
        # Count recipients
        recipient_count = len(to_recipients) + len(cc_recipients)
        
        # Check for undisclosed recipients
        has_undisclosed_recipients = False
        if to_header and ("undisclosed" in to_header.lower() or 
                         "recipients" in to_header.lower()):
            has_undisclosed_recipients = True
        
        # Check for BCC without other recipients
        has_bcc_only = False
        if recipient_count == 0 and self.headers.get("bcc", ""):
            has_bcc_only = True
        
        # Store features
        recipient_features["to_count"] = len(to_recipients)
        recipient_features["cc_count"] = len(cc_recipients)
        recipient_features["total_recipients"] = recipient_count
        recipient_features["has_undisclosed_recipients"] = has_undisclosed_recipients
        recipient_features["has_bcc_only"] = has_bcc_only
        
        self.extracted_attributes["recipient"] = recipient_features
    
    def extract_subject_features(self) -> None:
        """
        Extract features related to the subject of the email.
        """
        subject_features = {}
        
        # Get Subject header
        subject = self.headers.get("subject", "") or ""
        
        # Check for common phishing subject patterns
        contains_urgent = any(word in subject.lower() for word in 
                             ["urgent", "important", "attention", "immediate", "action"])
        
        contains_account = any(word in subject.lower() for word in 
                              ["account", "password", "login", "security", "verify"])
        
        contains_financial = any(word in subject.lower() for word in 
                                ["bank", "credit", "debit", "money", "payment", "invoice"])
        
        contains_prize = any(word in subject.lower() for word in 
                            ["prize", "winner", "won", "lottery", "reward"])
        
        # Check for excessive punctuation
        excessive_punctuation = len(re.findall(r'[!\?\$\*]', subject)) > 2
        
        # Check for all caps
        all_caps = False
        if subject and subject.isupper() and len(subject) > 5:
            all_caps = True
        
        # Store features
        subject_features["text"] = subject
        subject_features["length"] = len(subject)
        subject_features["contains_urgent"] = contains_urgent
        subject_features["contains_account"] = contains_account
        subject_features["contains_financial"] = contains_financial
        subject_features["contains_prize"] = contains_prize
        subject_features["excessive_punctuation"] = excessive_punctuation
        subject_features["all_caps"] = all_caps
        
        self.extracted_attributes["subject"] = subject_features
    
    def extract_date_features(self) -> None:
        """
        Extract features related to the date of the email.
        """
        date_features = {}
        
        # Get Date header
        date_header = self.headers.get("date", "")
        date_obj = None
        
        try:
            if date_header:
                date_obj = parsedate_to_datetime(date_header)
        except Exception as e:
            logger.debug(f"Error parsing date: {str(e)}")
        
        # Check for future date
        future_date = False
        if date_obj:
            # Make both datetimes timezone-aware for comparison
            now = datetime.now().replace(tzinfo=date_obj.tzinfo)
            if date_obj > now + timedelta(days=1):
                future_date = True
        
        # Check for very old date
        old_date = False
        if date_obj:
            # Make both datetimes timezone-aware for comparison
            now = datetime.now().replace(tzinfo=date_obj.tzinfo)
            if date_obj < now - timedelta(days=365):
                old_date = True
        
        # Check for time discrepancies in Received headers
        time_discrepancies = self._check_time_discrepancies()
        
        # Store features
        date_features["header_date"] = date_header
        date_features["parsed_date"] = date_obj.isoformat() if date_obj else None
        date_features["future_date"] = future_date
        date_features["old_date"] = old_date
        date_features["time_discrepancies"] = time_discrepancies
        
        self.extracted_attributes["date"] = date_features
    
    def extract_received_chain_features(self) -> None:
        """
        Extract features related to the Received headers chain.
        """
        chain_features = {}
        
        # Count Received headers
        received_count = len(self.received_chain)
        
        # Check for unusual chain length
        # Only consider too many hops as unusual - having few hops could be legitimate
        # especially for locally generated test emails
        unusual_chain_length = received_count > 10
        
        # Check for inconsistent routing
        inconsistent_routing = self._check_inconsistent_routing()
        
        # Check for suspicious IPs in chain
        suspicious_ips = self._check_suspicious_ips()
        
        # Check for missing hops
        missing_hops = self._check_missing_hops()
        
        # Store features
        chain_features["received_count"] = received_count
        chain_features["unusual_chain_length"] = unusual_chain_length
        chain_features["inconsistent_routing"] = inconsistent_routing
        chain_features["suspicious_ips"] = suspicious_ips
        chain_features["missing_hops"] = missing_hops
        chain_features["full_chain"] = self.received_chain
        
        self.extracted_attributes["received_chain"] = chain_features
    
    def extract_authentication_features(self) -> None:
        """
        Extract features related to email authentication.
        """
        auth_features = {}
        
        # Check for SPF
        spf_header = self.headers.get("received-spf", "")
        has_spf = bool(spf_header)
        spf_pass = "pass" in spf_header.lower() if spf_header else False
        
        # Check for DKIM
        dkim_header = self.headers.get("dkim-signature", "")
        has_dkim = bool(dkim_header)
        
        # Check for DMARC
        dmarc_header = self.headers.get("authentication-results", "")
        has_dmarc = "dmarc" in dmarc_header.lower() if dmarc_header else False
        dmarc_pass = "dmarc=pass" in dmarc_header.lower() if dmarc_header else False
        
        # Store features
        auth_features["has_spf"] = has_spf
        auth_features["spf_pass"] = spf_pass
        auth_features["has_dkim"] = has_dkim
        auth_features["has_dmarc"] = has_dmarc
        auth_features["dmarc_pass"] = dmarc_pass
        
        self.extracted_attributes["authentication"] = auth_features
    
    def extract_content_features(self) -> None:
        """
        Extract features related to email content type and encoding.
        """
        content_features = {}
        
        # Get Content-Type header
        content_type = self.headers.get("content-type", "")
        
        # Check for multipart
        is_multipart = "multipart" in content_type.lower() if content_type else False
        
        # Get Content-Transfer-Encoding header
        transfer_encoding = self.headers.get("content-transfer-encoding", "")
        
        # Check for unusual encoding
        unusual_encoding = (transfer_encoding or "").lower() not in ["", "7bit", "8bit", "base64", "quoted-printable"]
        
        # Store features
        content_features["content_type"] = content_type
        content_features["is_multipart"] = is_multipart
        content_features["transfer_encoding"] = transfer_encoding
        content_features["unusual_encoding"] = unusual_encoding
        
        self.extracted_attributes["content"] = content_features
    
    def extract_message_id_features(self) -> None:
        """
        Extract features related to the Message-ID header.
        """
        message_id_features = {}
        
        # Get Message-ID header
        message_id = self.headers.get("message-id", "")
        
        # Check if Message-ID exists
        has_message_id = bool(message_id)
        
        # Check for malformed Message-ID
        malformed_id = False
        if message_id and not re.match(r'^<[^@]+@[^>]+>$', message_id.strip()):
            malformed_id = True
        
        # Extract domain from Message-ID
        message_id_domain = ""
        if message_id and "@" in message_id:
            message_id_domain = message_id.split("@", 1)[1].split(">", 1)[0]
        
        # Check if Message-ID domain matches From domain
        sender_domain = self.extracted_attributes.get("sender", {}).get("from_domain", "")
        domain_mismatch = False
        
        if message_id_domain and sender_domain:
            # More lenient comparison - check if either domain contains the other
            # or if they share the same root domain (e.g. mail.company.com vs company.com)
            if not (message_id_domain in sender_domain or sender_domain in message_id_domain):
                # Compare root domains (last two parts)
                try:
                    msg_id_parts = message_id_domain.split(".")
                    sender_parts = sender_domain.split(".")
                    
                    # Only consider domain mismatch if both have at least 2 parts
                    # AND their root domains don't match
                    if (len(msg_id_parts) >= 2 and len(sender_parts) >= 2 and
                            msg_id_parts[-2:] != sender_parts[-2:]):
                        domain_mismatch = True
                except:
                    # If comparison fails, be conservative
                    domain_mismatch = False
            else:
                domain_mismatch = False
        else:
            domain_mismatch = True
        
        # Store features
        message_id_features["value"] = message_id
        message_id_features["has_message_id"] = has_message_id
        message_id_features["malformed"] = malformed_id
        message_id_features["domain"] = message_id_domain
        message_id_features["domain_mismatch"] = domain_mismatch
        
        self.extracted_attributes["message_id"] = message_id_features
    
    def _extract_domain(self, email: str) -> str:
        """
        Extract domain from an email address.
        
        Args:
            email: Email address
            
        Returns:
            Domain part of the email address
        """
        if not email or "@" not in email:
            return ""
        
        return email.split("@", 1)[1].lower()
    
    def _check_domain_has_mx(self, domain: str) -> bool:
        """
        Check if a domain has MX records.
        
        Args:
            domain: Domain to check
            
        Returns:
            True if domain has MX records, False otherwise
        """
        if not DNS_AVAILABLE:
            return False
        
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            return len(mx_records) > 0
        except Exception:
            return False
    
    def _check_domain_has_spf(self, domain: str) -> bool:
        """
        Check if a domain has SPF records.
        
        Args:
            domain: Domain to check
            
        Returns:
            True if domain has SPF records, False otherwise
        """
        if not DNS_AVAILABLE:
            return False
        
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            for record in txt_records:
                if "v=spf1" in str(record):
                    return True
            return False
        except Exception:
            return False
    
    def _check_domain_has_dmarc(self, domain: str) -> bool:
        """
        Check if a domain has DMARC records.
        
        Args:
            domain: Domain to check
            
        Returns:
            True if domain has DMARC records, False otherwise
        """
        if not DNS_AVAILABLE:
            return False
        
        try:
            dmarc_domain = f"_dmarc.{domain}"
            txt_records = dns.resolver.resolve(dmarc_domain, 'TXT')
            for record in txt_records:
                if "v=DMARC1" in str(record):
                    return True
            return False
        except Exception:
            return False
    
    def _check_time_discrepancies(self) -> bool:
        """
        Check for time discrepancies in the Received headers chain.
        
        Returns:
            True if time discrepancies found, False otherwise
        """
        if len(self.received_chain) < 2:
            return False
        
        # Extract dates from received headers
        dates = []
        for header in self.received_chain:
            date_str = header.get("date")
            if date_str:
                try:
                    # Handle ISO format from our parser
                    if 'T' in date_str:
                        date_obj = datetime.fromisoformat(date_str)
                    else:
                        date_obj = parsedate_to_datetime(date_str)
                    dates.append(date_obj)
                except Exception:
                    continue
        
        # Check for chronological inconsistencies
        if len(dates) >= 2:
            # Received headers are typically in reverse chronological order
            for i in range(len(dates) - 1):
                # If a later hop has an earlier timestamp (with 5 min tolerance)
                if dates[i] < dates[i+1] - timedelta(minutes=5):
                    return True
                # If time difference between hops is too large
                if dates[i] - dates[i+1] > timedelta(hours=24):
                    return True
        
        return False
    
    def _check_inconsistent_routing(self) -> bool:
        """
        Check for inconsistent routing in the Received headers chain.
        
        Returns:
            True if inconsistent routing found, False otherwise
        """
        if len(self.received_chain) < 2:
            return False
        
        # Check for inconsistent from/by patterns
        for i in range(len(self.received_chain) - 1):
            current = self.received_chain[i]
            next_hop = self.received_chain[i+1]
            
            # The 'by' field of the current hop should match the 'from' field of the next hop
            current_by = (current.get("by") or "").lower()
            next_from = (next_hop.get("from") or "").lower()
            
            # Extract domain parts for comparison
            if current_by and next_from:
                current_by_domain = current_by.split(".")[-2:] if len(current_by.split(".")) >= 2 else []
                next_from_domain = next_from.split(".")[-2:] if len(next_from.split(".")) >= 2 else []
                
                # If domains don't match at all and aren't empty
                if current_by_domain and next_from_domain and current_by_domain != next_from_domain:
                    # Check if they're not related subdomains
                    if current_by_domain[-1] != next_from_domain[-1] or current_by_domain[-2] != next_from_domain[-2]:
                        return True
        
        return False
    
    def _check_suspicious_ips(self) -> List[str]:
        """
        Check for suspicious IPs in the Received headers chain.
        
        Returns:
            List of suspicious IPs found
        """
        suspicious_ips = []
        
        for header in self.received_chain:
            ip = header.get("ip")
            if not ip:
                continue
            
            # Check for private IPs in external communication
            if self._is_private_ip(ip):
                suspicious_ips.append(ip)
            
            # Here you could add checks against IP reputation databases
            # if REQUESTS_AVAILABLE:
            #     if self._check_ip_reputation(ip):
            #         suspicious_ips.append(ip)
        
        return suspicious_ips
    
    def _is_private_ip(self, ip: str) -> bool:
        """
        Check if an IP address is private.
        
        Args:
            ip: IP address to check
            
        Returns:
            True if IP is private, False otherwise
        """
        try:
            # Check for private IP ranges
            octets = [int(octet) for octet in ip.split('.')]
            
            # 10.0.0.0/8
            if octets[0] == 10:
                return True
            
            # 172.16.0.0/12
            if octets[0] == 172 and 16 <= octets[1] <= 31:
                return True
            
            # 192.168.0.0/16
            if octets[0] == 192 and octets[1] == 168:
                return True
            
            # 127.0.0.0/8 (localhost)
            if octets[0] == 127:
                return True
            
            return False
        except Exception:
            return False
    
    def _check_missing_hops(self) -> bool:
        """
        Check for missing hops in the Received headers chain.
        
        Returns:
            True if missing hops detected, False otherwise
        """
        if len(self.received_chain) < 2:
            return False
        
        # Check for large gaps in IP addresses
        ips = []
        for header in self.received_chain:
            ip = header.get("ip")
            if ip:
                ips.append(ip)
        
        if len(ips) < 2:
            return False
        
        # Check for IP subnet jumps
        for i in range(len(ips) - 1):
            current_ip = ips[i]
            next_ip = ips[i+1]
            
            # Convert to octets
            current_octets = [int(octet) for octet in current_ip.split('.')]
            next_octets = [int(octet) for octet in next_ip.split('.')]
            
            # Check for large subnet jumps (simplified check)
            if abs(current_octets[0] - next_octets[0]) > 1:
                return True
        
        return False


if __name__ == "__main__":
    # Simple test if run directly
    import sys
    from email_parser import EmailParser
    
    if len(sys.argv) > 1:
        from email_parser import EmailHeaderAnalyzer
        
        analyzer = EmailHeaderAnalyzer(sys.argv[1])
        parsed_content = analyzer.process_email()
        
        extractor = EmailAttributeExtractor(parsed_content)
        extracted_attributes = extractor.collect_header_attributes()
        
        print("Extracted Attributes:")
        print(f"Sender: {extracted_attributes.get('sender', {})}")
        print(f"Subject: {extracted_attributes.get('subject', {}).get('text', '')}")
        print(f"Authentication: {extracted_attributes.get('authentication', {})}")
        
        # Check for suspicious indicators
        sender = extracted_attributes.get('sender', {})
        if sender.get('domain_mismatch'):
            print("WARNING: Sender domain mismatch detected!")
        if sender.get('email_mismatch'):
            print("WARNING: From/Reply-To email mismatch detected!")
    else:
        print("Please provide an email file path as argument")
