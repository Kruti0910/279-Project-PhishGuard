#!/usr/bin/env python3
"""
Utilities Module

This module provides utility functions for the phishing detection system.
"""

import os
import logging
from pathlib import Path
from typing import List, Optional
import re


def setup_logger(log_level: int = logging.INFO) -> logging.Logger:
    """
    Set up and configure the logger.
    
    Args:
        log_level: Logging level (default: INFO)
        
    Returns:
        Configured logger instance
    """
    # Create logger
    logger = logging.getLogger("phishing_detector")
    logger.setLevel(log_level)
    
    # Create console handler and set level
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    
    # Create formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    # Add formatter to console handler
    console_handler.setFormatter(formatter)
    
    # Add console handler to logger
    logger.addHandler(console_handler)
    
    return logger


def get_file_list(directory: str, extensions: Optional[List[str]] = None) -> List[str]:
    """
    Get a list of files in a directory with specified extensions.
    
    Args:
        directory: Directory path to search
        extensions: List of file extensions to include (e.g., [".eml", ".msg"])
        
    Returns:
        List of file paths
    """
    if not os.path.isdir(directory):
        return []
    
    files = []
    
    # Convert extensions to lowercase for case-insensitive matching
    if extensions:
        extensions = [ext.lower() for ext in extensions]
    
    # Walk through directory
    for root, _, filenames in os.walk(directory):
        for filename in filenames:
            # Check if file has one of the specified extensions
            if extensions:
                if any(filename.lower().endswith(ext) for ext in extensions):
                    files.append(os.path.join(root, filename))
            else:
                files.append(os.path.join(root, filename))
    
    return files


def extract_email_parts(email_text: str) -> dict:
    """
    Extract headers and body from a raw email text.
    
    Args:
        email_text: Raw email text
        
    Returns:
        Dictionary containing headers and body
    """
    result = {
        "headers": {},
        "body": ""
    }
    
    # Split headers and body
    parts = re.split(r'\n\s*\n', email_text, 1)
    
    if len(parts) > 1:
        header_text, result["body"] = parts
    else:
        header_text = parts[0]
        result["body"] = ""
    
    # Parse headers
    header_lines = header_text.split('\n')
    current_header = None
    current_value = ""
    
    for line in header_lines:
        # New header
        if re.match(r'^[A-Za-z\-]+:', line):
            # Save previous header if exists
            if current_header:
                result["headers"][current_header.lower()] = current_value.strip()
            
            # Start new header
            parts = line.split(':', 1)
            current_header = parts[0].strip()
            current_value = parts[1].strip() if len(parts) > 1 else ""
        # Continuation of previous header
        elif current_header and line.startswith(' '):
            current_value += " " + line.strip()
    
    # Save the last header
    if current_header:
        result["headers"][current_header.lower()] = current_value.strip()
    
    return result


def is_valid_email(email: str) -> bool:
    """
    Check if a string is a valid email address.
    
    Args:
        email: Email address to check
        
    Returns:
        True if valid, False otherwise
    """
    # Basic email validation pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def format_header_value(value: str) -> str:
    """
    Format a header value for display, handling long values.
    
    Args:
        value: Header value
        
    Returns:
        Formatted header value
    """
    # Truncate long values
    if len(value) > 70:
        return value[:67] + "..."
    return value


def create_sample_directories(base_dir: str) -> None:
    """
    Create sample directories for storing email samples.
    
    Args:
        base_dir: Base directory path
    """
    # Create data directory
    data_dir = os.path.join(base_dir, "data")
    os.makedirs(data_dir, exist_ok=True)
    
    # Create legitimate and phishing subdirectories
    legitimate_dir = os.path.join(data_dir, "legitimate")
    phishing_dir = os.path.join(data_dir, "phishing")
    
    os.makedirs(legitimate_dir, exist_ok=True)
    os.makedirs(phishing_dir, exist_ok=True)