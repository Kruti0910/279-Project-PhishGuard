#!/usr/bin/env python3
"""
Email Security Evaluation System Using Header Analysis

This script evaluates email headers to identify potential security threats
based on various heuristic-based security rules and patterns.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Union, Optional
from tqdm import tqdm
from colorama import init, Fore, Style

# Import local modules
from email_parser import EmailHeaderAnalyzer
from feature_extractor import EmailAttributeExtractor
from detection_rules import SuspiciousEmailDetector
from utils import setup_logger, get_file_list

# Initialize colorama for cross-platform colored terminal output
init()

# Setup logger
logger = setup_logger()


def analyze_email(email_path: str, evaluator: SuspiciousEmailDetector) -> Dict:
    """Evaluate a single email file and return security assessment results"""
    try:
        # Verify file exists
        if not Path(email_path).exists():
            return {
                "file": email_path,
                "status": "error",
                "message": "File not found"
            }

        # Process email
        analyzer = EmailHeaderAnalyzer(email_path)
        parsed_content = analyzer.process_email()
        
        if not parsed_content:
            return {
                "file": email_path,
                "status": "error",
                "message": "Failed to process email file"
            }
        
        # Collect header attributes
        extractor = EmailAttributeExtractor(parsed_content)
        extracted_attributes = extractor.collect_header_attributes()
        
        # Evaluate email security
        evaluation_result = evaluator.evaluate_email(extracted_attributes)
        evaluation_result["file"] = email_path
        
        return evaluation_result
        
    except Exception as e:
        logger.error(f"Error evaluating {email_path}: {str(e)}")
        return {
            "file": email_path,
            "status": "error",
            "message": str(e)
        }


def display_result(result: Dict) -> None:
    """
    Display analysis result in a user-friendly format.
    
    Args:
        result: Analysis result dictionary
    """
    print("\n" + "=" * 80)
    print(f"File: {result['file']}")
    
    if result.get("status") == "error":
        print(f"{Fore.RED}Error: {result['message']}{Style.RESET_ALL}")
        return
    
    # Display phishing probability and classification
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
    
    # Display header analysis
    if "header_analysis" in result:
        print("\nHeader Analysis:")
        for header, analysis in result["header_analysis"].items():
            status = analysis.get("status", "")
            if status == "suspicious":
                print(f" - {Fore.YELLOW}{header}{Style.RESET_ALL}: {analysis.get('value', '')}")
                print(f"   {analysis.get('reason', '')}")
            elif status == "safe":
                print(f" - {header}: {analysis.get('value', '')}")
    
    print("=" * 80)


def save_results(results: List[Dict], output_file: str) -> None:
    """
    Save analysis results to a JSON file with additional metadata.
    """
    try:
        import datetime  # Add missing import
        output_dir = Path(output_file).parent
        output_dir.mkdir(parents=True, exist_ok=True)  # Create directory if needed
        
        output_data = {
            "metadata": {
                "analysis_date": datetime.datetime.now().isoformat(),
                "total_files": len(results),
                "system_version": "1.0"
            },
            "results": results,
            "statistics": {
                "phishing_count": sum(1 for r in results if r.get("is_phishing", False)),
                "legitimate_count": sum(1 for r in results if not r.get("is_phishing", False)),
                "error_count": sum(1 for r in results if r.get("status") == "error")
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2, default=lambda o: str(o) if isinstance(o, Path) else o)
            
        print(f"\nResults saved to {output_file}")
        print(f"Successfully wrote {len(results)} entries to:")
        print(f" - Path: {Path(output_file).resolve()}")
        print(f" - Size: {Path(output_file).stat().st_size} bytes")
        
    except Exception as e:
        logger.error(f"Failed to save results: {str(e)}")
        print(f"{Fore.RED}Error saving results:{Style.RESET_ALL}")
        print(f" - Error type: {type(e).__name__}")
        print(f" - Details: {str(e)}")
        if Path(output_file).exists():
            print(f" - Partial file exists at: {output_file}")


def main():
    """
    Main function to parse arguments and run the phishing detection.
    """
    parser = argparse.ArgumentParser(
        description="Phishing Detection System Using Email Header Analysis"
    )
    
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--file", "-f", type=str, help="Path to a single email file for analysis"
    )
    input_group.add_argument(
        "--dir", "-d", type=str, help="Path to a directory containing email files"
    )
    
    parser.add_argument(
        "--output", "-o", type=str, help="Path to save the analysis results as JSON"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    # Initialize the security evaluator
    evaluator = SuspiciousEmailDetector(verbose=args.verbose)
    
    # Get list of files to analyze
    if args.file:
        if not os.path.isfile(args.file):
            print(f"Error: File not found - {args.file}")
            sys.exit(1)
        files = [args.file]
    else:  # args.dir
        if not os.path.isdir(args.dir):
            print(f"Error: Directory not found - {args.dir}")
            sys.exit(1)
        # Modified to include extensionless files and recursive search
        files = get_file_list(args.dir, extensions=[".eml", ".msg", ".txt", ""])
        if not files:
            print(f"No email files found in {args.dir}")
            print(f"Supported patterns: *.eml, *.msg, *.txt, and extensionless files")
            sys.exit(1)
    
    # Analyze emails
    results = []
    print(f"Analyzing {len(files)} email file(s)...")
    
    for file_path in tqdm(files, desc="Processing"):
        result = analyze_email(file_path, evaluator)
        results.append(result)
        
        # Display result immediately if it's a single file
        if args.file:
            display_result(result)
    
    # Summary for multiple files
    if args.dir:
        # Existing counts
        phishing_count = sum(1 for r in results if r.get("is_phishing", False))
        legitimate_count = len(results) - phishing_count
        error_count = sum(1 for r in results if r.get("status") == "error")
        
        # New metrics
        true_positives = sum(1 for r in results 
                           if r.get("is_phishing") and "phishing" in r["file"])
        false_positives = sum(1 for r in results 
                            if r.get("is_phishing") and "legitimate" in r["file"])
        true_negatives = sum(1 for r in results 
                           if not r.get("is_phishing") and "legitimate" in r["file"])
        false_negatives = sum(1 for r in results 
                            if not r.get("is_phishing") and "phishing" in r["file"])

        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        print(f"\nDetection Metrics:")
        print(f" - Precision: {precision:.2%} (Correct phishing identifications)")
        print(f" - Recall:    {recall:.2%} (Phishing emails detected)")
        print(f" - F1 Score:  {f1_score:.2%} (Balance between precision/recall)")
        
        print(f"\nConfusion Matrix:")
        print(f" {'Actual →':<15} {'Predicted ↓':>15}")
        print(f" {'Phishing':<15} {'Legitimate':>15}")
        print(f"Phishing {true_positives:>7} {'':<5} {false_negatives:>7}")
        print(f"Legitimate{false_positives:>7} {'':<5} {true_negatives:>7}")
        
        print(f"\nAnalysis complete for {len(files)} email file(s):")
        print(f" - {Fore.RED}Potential phishing emails: {phishing_count}{Style.RESET_ALL}")
        print(f" - {Fore.GREEN}Likely legitimate emails: {legitimate_count}{Style.RESET_ALL}")
        if error_count > 0:
            print(f" - {Fore.YELLOW}Files with errors: {error_count}{Style.RESET_ALL}")
        
        # Display detailed results for phishing emails
        if phishing_count > 0:
            print("\nDetailed results for potential phishing emails:")
            for result in results:
                if result.get("is_phishing", False):
                    display_result(result)
    
    # Save results if output file is specified
    if args.output:
        save_results(results, args.output)


if __name__ == "__main__":
    main()