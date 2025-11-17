#!/usr/bin/env python3
"""
Test Script for Phishing Detection System

This script demonstrates how to use the phishing detection system
with sample email files.
"""

import os
import argparse
import json
from colorama import init, Fore, Style

# Import local modules
from email_parser import EmailParser
from feature_extractor import FeatureExtractor
from detection_rules import PhishingDetector
from utils import setup_logger

# Initialize colorama for cross-platform colored terminal output
init()

# Setup logger
logger = setup_logger()


def analyze_sample(email_path: str, verbose: bool = False) -> None:
    """
    Analyze a sample email file and display the results.
    
    Args:
        email_path: Path to the email file
        verbose: Whether to display detailed analysis
    """
    print(f"\nAnalyzing: {email_path}")
    print("-" * 50)
    
    # Parse email
    parser = EmailParser(email_path)
    email_data = parser.parse()
    
    if not email_data:
        print(f"{Fore.RED}Error: Failed to parse email file{Style.RESET_ALL}")
        return
    
    # Extract basic info for display
    from_header = email_data.get("headers", {}).get("from", "Unknown")
    subject = email_data.get("headers", {}).get("subject", "No Subject")
    date = email_data.get("headers", {}).get("date", "Unknown")
    
    print(f"From: {from_header}")
    print(f"Subject: {subject}")
    print(f"Date: {date}")
    print("-" * 50)
    
    # Extract features
    extractor = FeatureExtractor(email_data)
    features = extractor.extract_all_features()
    
    # Detect phishing
    detector = PhishingDetector(verbose=verbose)
    result = detector.analyze(features)
    
    # Display result
    probability = result.get("phishing_probability", 0)
    is_phishing = result.get("is_phishing", False)
    
    if is_phishing:
        print(f"{Fore.RED}VERDICT: POTENTIAL PHISHING EMAIL{Style.RESET_ALL}")
        print(f"Confidence: {probability:.2f}%")
    else:
        print(f"{Fore.GREEN}VERDICT: LIKELY LEGITIMATE EMAIL{Style.RESET_ALL}")
        print(f"Confidence: {(100-probability):.2f}%")
    
    # Display detected indicators
    if "indicators" in result and result["indicators"]:
        print("\nSuspicious indicators detected:")
        for indicator in result["indicators"]:
            print(f" - {Fore.YELLOW}{indicator['name']}{Style.RESET_ALL}: {indicator['description']}")
    else:
        print("\nNo suspicious indicators detected.")
    
    # Display header analysis if verbose
    if verbose and "header_analysis" in result:
        print("\nDetailed Header Analysis:")
        for header, analysis in result["header_analysis"].items():
            status = analysis.get("status", "")
            if status == "suspicious":
                print(f" - {Fore.YELLOW}{header}{Style.RESET_ALL}: {analysis.get('value', '')}")
                print(f"   {analysis.get('reason', '')}")
            elif status == "safe":
                print(f" - {header}: {analysis.get('value', '')}")


def main():
    """
    Main function to parse arguments and run the test.
    """
    parser = argparse.ArgumentParser(
        description="Test the Phishing Detection System with sample emails"
    )
    
    parser.add_argument(
        "--sample", "-s", 
        choices=["legitimate", "phishing", "both"], 
        default="both",
        help="Which sample emails to analyze"
    )
    
    parser.add_argument(
        "--verbose", "-v", 
        action="store_true", 
        help="Display detailed analysis"
    )
    
    args = parser.parse_args()
    
    # Get sample file paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(script_dir, "data")
    
    legitimate_sample = os.path.join(data_dir, "legitimate", "sample_legitimate.eml")
    phishing_sample = os.path.join(data_dir, "phishing", "sample_phishing.eml")
    
    # Check if sample files exist
    if not os.path.exists(legitimate_sample):
        print(f"Warning: Legitimate sample file not found at {legitimate_sample}")
    
    if not os.path.exists(phishing_sample):
        print(f"Warning: Phishing sample file not found at {phishing_sample}")
    
    # Analyze samples based on user choice
    if args.sample in ["legitimate", "both"] and os.path.exists(legitimate_sample):
        print(f"\n{Fore.CYAN}Testing with legitimate email sample:{Style.RESET_ALL}")
        analyze_sample(legitimate_sample, args.verbose)
    
    if args.sample in ["phishing", "both"] and os.path.exists(phishing_sample):
        print(f"\n{Fore.CYAN}Testing with phishing email sample:{Style.RESET_ALL}")
        analyze_sample(phishing_sample, args.verbose)


if __name__ == "__main__":
    main()