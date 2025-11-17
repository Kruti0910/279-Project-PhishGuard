#!/usr/bin/env python3
"""
Email Security Evaluation Rules Module

This module implements heuristic-based security rules for evaluating suspicious emails
based on attributes extracted from email headers.
"""

import re
from typing import Dict, List, Optional, Union, Tuple, Any
import logging

logger = logging.getLogger(__name__)

# Define security rule scores for risk calculation
SECURITY_RULE_SCORES = {
    # Sender-related rules
    "sender_address_inconsistency": 25,
    "return_path_address_mismatch": 20,
    "free_email_in_business_context": 15,
    "display_name_has_email_address": 10,
    "sender_domain_missing": 20,
    "domain_mx_records_missing": 15,
    "domain_spf_record_missing": 10,
    "domain_dmarc_record_missing": 10,
    
    # Recipient-related rules
    "undisclosed_recipient_list": 15,
    "bcc_only_recipients": 20,
    "too_many_recipients": 10,
    
    # Subject-related rules
    "urgency_keywords_in_subject": 15,
    "account_keywords_in_subject": 15,
    "financial_keywords_in_subject": 15,
    "prize_keywords_in_subject": 20,
    "excessive_punctuation_in_subject": 10,
    "subject_line_all_caps": 15,
    
    # Date-related rules
    "future_dated_email": 25,
    "very_old_dated_email": 15,
    "timestamp_inconsistencies": 20,
    
    # Received chain rules
    "abnormal_chain_length": 15,
    "irregular_routing_pattern": 25,
    "suspicious_ip_addresses": 20,
    "missing_chain_hops": 15,
    
    # Authentication rules
    "spf_authentication_failure": 25,
    "dkim_signature_missing": 15,
    "dmarc_policy_failure": 20,
    
    # Message-ID rules
    "message_id_missing": 15,
    "message_id_format_invalid": 20,
    "message_id_domain_inconsistency": 20,
    
    # Content rules
    "unusual_content_encoding": 15
}


class SuspiciousEmailDetector:
    """Class for evaluating email security using heuristic-based rules."""
    
    def __init__(self, threshold: float = 50.0, verbose: bool = False):
        """
        Initialize the SuspiciousEmailDetector with a risk threshold score.
        
        Args:
            threshold: Risk score threshold for classifying an email as suspicious (0-100)
            verbose: Whether to include detailed evaluation in results
        """
        self.threshold = threshold
        self.verbose = verbose
        self.triggered_rules = []
        self.header_evaluation = {}
    
    def evaluate_email(self, extracted_attributes: Dict) -> Dict:
        """
        Evaluate email attributes to identify suspicious security indicators.
        
        Args:
            extracted_attributes: Dictionary containing extracted email header attributes
            
        Returns:
            Dictionary containing evaluation results and security assessment
        """
        # Reset state for new evaluation
        self.triggered_rules = []
        self.header_evaluation = {}
        
        # Apply all security evaluation rules
        self._evaluate_sender_rules(extracted_attributes)
        self._evaluate_recipient_rules(extracted_attributes)
        self._evaluate_subject_rules(extracted_attributes)
        self._evaluate_date_rules(extracted_attributes)
        self._evaluate_received_chain_rules(extracted_attributes)
        self._evaluate_authentication_rules(extracted_attributes)
        self._evaluate_message_id_rules(extracted_attributes)
        self._evaluate_content_rules(extracted_attributes)
        
        # Compute security risk probability score
        risk_score = self._compute_risk_score()
        is_suspicious = risk_score >= self.threshold
        
        # Construct evaluation result
        evaluation_result = {
            "is_phishing": is_suspicious,
            "phishing_probability": risk_score,
            "indicators": self.triggered_rules,
        }
        
        # Include detailed header evaluation if verbose mode enabled
        if self.verbose:
            evaluation_result["header_analysis"] = self.header_evaluation
        
        return evaluation_result
    
    def _evaluate_sender_rules(self, extracted_attributes: Dict) -> None:
        """
        Evaluate sender-related security indicators.
        
        Args:
            extracted_attributes: Dictionary containing extracted email header attributes
        """
        sender = extracted_attributes.get("sender", {})
        
        # Evaluate From and Reply-To address consistency
        if sender.get("email_mismatch"):
            self._add_indicator(
                "sender_address_inconsistency",
                "From and Reply-To addresses don't match",
                f"From: {sender.get('from_email')} vs Reply-To: {sender.get('reply_to_email')}"
            )
            
            # Add to header evaluation
            self._add_header_evaluation("from", sender.get("from_email"), "safe")
            self._add_header_evaluation(
                "reply-to", 
                sender.get("reply_to_email"), 
                "suspicious", 
                "Doesn't match From address"
            )
        
        # Evaluate domain consistency
        if sender.get("domain_mismatch"):
            self._add_indicator(
                "from_reply_to_mismatch",
                "From and Reply-To domains don't match",
                f"From domain: {sender.get('from_domain')} vs Reply-To domain: {sender.get('reply_to_domain')}"
            )
        
        # Check Return-Path mismatch
        return_path = sender.get("return_path_email")
        from_email = sender.get("from_email")
        
        if return_path and from_email and return_path != from_email:
            self._add_indicator(
                "from_return_path_mismatch",
                "From and Return-Path addresses don't match",
                f"From: {from_email} vs Return-Path: {return_path}"
            )
            
            # Add to header analysis
            self._add_header_evaluation(
                "return-path", 
                return_path, 
                "suspicious", 
                "Doesn't match From address"
            )
        
        # Check for free email provider in business context
        if sender.get("is_free_provider"):
            # This is a weak signal, so we'll only flag it if it looks like a business email
            from_name = sender.get("from_name", "")
            if from_name and ("inc" in from_name.lower() or 
                             "corp" in from_name.lower() or 
                             "ltd" in from_name.lower() or 
                             "company" in from_name.lower() or
                             "enterprise" in from_name.lower()):
                self._add_indicator(
                    "free_provider_business_context",
                    "Business sender using free email provider",
                    f"Sender '{from_name}' using {sender.get('from_domain')}"
                )
                
                # Add to header analysis
                self._add_header_evaluation(
                    "from", 
                    sender.get("from_email"), 
                    "suspicious", 
                    "Business sender using free email provider"
                )
        
        # Check for display name containing email
        if sender.get("display_name_contains_email"):
            self._add_indicator(
                "display_name_contains_email",
                "Display name contains an email address",
                f"Display name: {sender.get('from_name')}"
            )
            
            # Add to header analysis
            self._add_header_evaluation(
                "from", 
                f"{sender.get('from_name')} <{sender.get('from_email')}>", 
                "suspicious", 
                "Display name contains an email address"
            )
        
        # Check for missing sender domain
        if not sender.get("from_domain"):
            self._add_indicator(
                "missing_sender_domain",
                "Sender email has no domain",
                f"From: {sender.get('from_email')}"
            )
            
            # Add to header analysis
            self._add_header_evaluation(
                "from", 
                sender.get("from_email"), 
                "suspicious", 
                "Sender email has no domain"
            )
        
        # Check for domain without MX records
        if sender.get("from_domain") and "domain_has_mx" in sender and not sender.get("domain_has_mx"):
            self._add_indicator(
                "domain_no_mx",
                "Sender domain has no MX records",
                f"Domain: {sender.get('from_domain')}"
            )
            
            # Add to header analysis
            self._add_header_evaluation(
                "from", 
                sender.get("from_email"), 
                "suspicious", 
                "Sender domain has no MX records"
            )
        
        # Check for domain without SPF
        if sender.get("from_domain") and "domain_has_spf" in sender and not sender.get("domain_has_spf"):
            self._add_indicator(
                "domain_no_spf",
                "Sender domain has no SPF records",
                f"Domain: {sender.get('from_domain')}"
            )
        
        # Check for domain without DMARC
        if sender.get("from_domain") and "domain_has_dmarc" in sender and not sender.get("domain_has_dmarc"):
            self._add_indicator(
                "domain_no_dmarc",
                "Sender domain has no DMARC records",
                f"Domain: {sender.get('from_domain')}"
            )
    
    def _evaluate_recipient_rules(self, extracted_attributes: Dict) -> None:
        """
        Evaluate recipient-related security indicators.
        
        Args:
            extracted_attributes: Dictionary containing extracted email header attributes
        """
        recipient = extracted_attributes.get("recipient", {})
        
        # Check for undisclosed recipients
        if recipient.get("has_undisclosed_recipients"):
            self._add_indicator(
                "undisclosed_recipient_list",
                "Email sent to undisclosed recipients",
                "The To field contains 'undisclosed recipients'"
            )
            
            # Add to header analysis
            self._add_header_evaluation(
                "to", 
                "undisclosed recipients", 
                "suspicious", 
                "Email sent to undisclosed recipients"
            )
        
        # Check for BCC only
        if recipient.get("has_bcc_only"):
            self._add_indicator(
                "bcc_only_recipients",
                "Email sent using BCC only",
                "No visible recipients in To or CC fields"
            )
            
            # Add to header analysis
            self._add_header_evaluation(
                "to", 
                "(empty)", 
                "suspicious", 
                "Email sent using BCC only"
            )
        
        # Check for excessive recipients
        total_recipients = recipient.get("total_recipients", 0)
        if total_recipients > 15:  # Arbitrary threshold
            self._add_indicator(
                "too_many_recipients",
                "Email sent to an unusually large number of recipients",
                f"Total recipients: {total_recipients}"
            )
            
            # Add to header analysis
            self._add_header_evaluation(
                "to/cc", 
                f"{total_recipients} recipients", 
                "suspicious", 
                "Unusually large number of recipients"
            )
    
    def _evaluate_subject_rules(self, extracted_attributes: Dict) -> None:
        """
        Evaluate subject-related security indicators.
        
        Args:
            extracted_attributes: Dictionary containing extracted email header attributes
        """
        subject = extracted_attributes.get("subject", {})
        subject_text = subject.get("text", "")
        
        # Check for urgent language
        if subject.get("contains_urgent"):
            self._add_indicator(
                "urgency_keywords_in_subject",
                "Subject contains urgent language",
                f"Subject: {subject_text}"
            )
            
            # Add to header analysis
            self._add_header_evaluation(
                "subject", 
                subject_text, 
                "suspicious", 
                "Contains urgent language"
            )
        
        # Check for account-related language
        if subject.get("contains_account"):
            self._add_indicator(
                "account_keywords_in_subject",
                "Subject contains account-related language",
                f"Subject: {subject_text}"
            )
            
            # Add to header analysis if not already added
            if "subject" not in self.header_evaluation:
                self._add_header_evaluation(
                    "subject", 
                    subject_text, 
                    "suspicious", 
                    "Contains account-related language"
                )
        
        # Check for financial language
        if subject.get("contains_financial"):
            self._add_indicator(
                "financial_keywords_in_subject",
                "Subject contains financial language",
                f"Subject: {subject_text}"
            )
            
            # Add to header analysis if not already added
            if "subject" not in self.header_evaluation:
                self._add_header_evaluation(
                    "subject", 
                    subject_text, 
                    "suspicious", 
                    "Contains financial language"
                )
        
        # Check for prize-related language
        if subject.get("contains_prize"):
            self._add_indicator(
                "prize_keywords_in_subject",
                "Subject contains prize-related language",
                f"Subject: {subject_text}"
            )
            
            # Add to header analysis if not already added
            if "subject" not in self.header_evaluation:
                self._add_header_evaluation(
                    "subject", 
                    subject_text, 
                    "suspicious", 
                    "Contains prize-related language"
                )
        
        # Check for excessive punctuation
        if subject.get("excessive_punctuation"):
            self._add_indicator(
                "excessive_punctuation_in_subject",
                "Subject contains excessive punctuation",
                f"Subject: {subject_text}"
            )
            
            # Add to header analysis if not already added
            if "subject" not in self.header_evaluation:
                self._add_header_evaluation(
                    "subject", 
                    subject_text, 
                    "suspicious", 
                    "Contains excessive punctuation"
                )
        
        # Check for all caps
        if subject.get("all_caps"):
            self._add_indicator(
                "subject_line_all_caps",
                "Subject is in all capital letters",
                f"Subject: {subject_text}"
            )
            
            # Add to header analysis if not already added
            if "subject" not in self.header_evaluation:
                self._add_header_evaluation(
                    "subject", 
                    subject_text, 
                    "suspicious", 
                    "Written in all capital letters"
                )
    
    def _evaluate_date_rules(self, extracted_attributes: Dict) -> None:
        """
        Evaluate date-related security indicators.
        
        Args:
            extracted_attributes: Dictionary containing extracted email header attributes
        """
        date = extracted_attributes.get("date", {})
        
        # Check for future date
        if date.get("future_date"):
            self._add_indicator(
                "future_dated_email",
                "Email has a future date",
                f"Date: {date.get('header_date')}"
            )
            
            # Add to header analysis
            self._add_header_evaluation(
                "date", 
                date.get("header_date"), 
                "suspicious", 
                "Email has a future date"
            )
        
        # Check for very old date
        if date.get("old_date"):
            self._add_indicator(
                "very_old_dated_email",
                "Email has a very old date",
                f"Date: {date.get('header_date')}"
            )
            
            # Add to header analysis
            self._add_header_evaluation(
                "date", 
                date.get("header_date"), 
                "suspicious", 
                "Email has a very old date"
            )
        
        # Check for time discrepancies
        if date.get("time_discrepancies"):
            self._add_indicator(
                "timestamp_inconsistencies",
                "Time discrepancies in email headers",
                "Inconsistent timestamps in Received headers"
            )
            
            # Add to header analysis
            self._add_header_evaluation(
                "received", 
                "Multiple headers", 
                "suspicious", 
                "Time discrepancies between Received headers"
            )
    
    def _evaluate_received_chain_rules(self, extracted_attributes: Dict) -> None:
        """
        Evaluate received chain-related security indicators.
        
        Args:
            extracted_attributes: Dictionary containing extracted email header attributes
        """
        chain = extracted_attributes.get("received_chain", {})
        
        # Check for unusual chain length
        if chain.get("unusual_chain_length"):
            count = chain.get("received_count", 0)
            reason = "Too many hops" if count > 10 else "Too few hops"
            
            self._add_indicator(
                "abnormal_chain_length",
                f"Unusual number of mail servers in delivery path",
                f"{reason} ({count} servers)"
            )
            
            # Add to header analysis
            self._add_header_evaluation(
                "received", 
                f"{count} headers", 
                "suspicious", 
                f"Unusual number of mail servers in delivery path"
            )
        
        # Check for inconsistent routing
        if chain.get("inconsistent_routing"):
            self._add_indicator(
                "irregular_routing_pattern",
                "Inconsistent mail routing detected",
                "Mail server chain has unexpected routing patterns"
            )
            
            # Add to header analysis
            self._add_header_evaluation(
                "received", 
                "Multiple headers", 
                "suspicious", 
                "Inconsistent mail routing detected"
            )
        
        # Check for suspicious IPs
        suspicious_ips = chain.get("suspicious_ips", [])
        if suspicious_ips:
            self._add_indicator(
                "suspicious_ip_addresses",
                "Suspicious IP addresses in mail routing",
                f"Suspicious IPs: {', '.join(suspicious_ips)}"
            )
            
            # Add to header analysis
            self._add_header_evaluation(
                "received", 
                f"Contains IPs: {', '.join(suspicious_ips)}", 
                "suspicious", 
                "Suspicious IP addresses in mail routing"
            )
        
        # Check for missing hops
        if chain.get("missing_hops"):
            self._add_indicator(
                "missing_chain_hops",
                "Missing hops in mail routing chain",
                "Unexpected gaps in the mail server chain"
            )
            
            # Add to header analysis
            self._add_header_evaluation(
                "received", 
                "Multiple headers", 
                "suspicious", 
                "Missing hops in mail routing chain"
            )
    
    def _evaluate_authentication_rules(self, extracted_attributes: Dict) -> None:
        """
        Evaluate authentication-related security indicators.
        
        Args:
            extracted_attributes: Dictionary containing extracted email header attributes
        """
        auth = extracted_attributes.get("authentication", {})
        
        # Check for SPF failure
        if auth.get("has_spf") and not auth.get("spf_pass"):
            self._add_indicator(
                "spf_authentication_failure",
                "SPF authentication failed",
                "Email failed Sender Policy Framework verification"
            )
            
            # Add to header analysis
            self._add_header_evaluation(
                "received-spf", 
                "fail", 
                "suspicious", 
                "SPF authentication failed"
            )
        
        # Check for missing DKIM
        if not auth.get("has_dkim"):
            self._add_indicator(
                "dkim_signature_missing",
                "No DKIM signature",
                "Email lacks DomainKeys Identified Mail signature"
            )
        
        # Check for DMARC failure
        if auth.get("has_dmarc") and not auth.get("dmarc_pass"):
            self._add_indicator(
                "dmarc_policy_failure",
                "DMARC authentication failed",
                "Email failed Domain-based Message Authentication verification"
            )
            
            # Add to header analysis
            self._add_header_evaluation(
                "authentication-results", 
                "dmarc=fail", 
                "suspicious", 
                "DMARC authentication failed"
            )
    
    def _evaluate_message_id_rules(self, extracted_attributes: Dict) -> None:
        """
        Evaluate Message-ID-related security indicators.
        
        Args:
            extracted_attributes: Dictionary containing extracted email header attributes
        """
        message_id = extracted_attributes.get("message_id", {})
        
        # Check for missing Message-ID
        if not message_id.get("has_message_id"):
            self._add_indicator(
                "message_id_missing",
                "Missing Message-ID header",
                "Email does not have a Message-ID header"
            )
            
            # Add to header analysis
            self._add_header_evaluation(
                "message-id", 
                "(missing)", 
                "suspicious", 
                "Missing Message-ID header"
            )
        
        # Check for malformed Message-ID
        if message_id.get("malformed"):
            self._add_indicator(
                "message_id_format_invalid",
                "Malformed Message-ID header",
                f"Message-ID: {message_id.get('value')}"
            )
            
            # Add to header analysis
            self._add_header_evaluation(
                "message-id", 
                message_id.get("value"), 
                "suspicious", 
                "Malformed Message-ID format"
            )
        
        # Check for domain mismatch
        if message_id.get("domain_mismatch"):
            self._add_indicator(
                "message_id_domain_inconsistency",
                "Message-ID domain doesn't match sender",
                f"Message-ID domain: {message_id.get('domain')}"
            )
            
            # Add to header analysis
            self._add_header_evaluation(
                "message-id", 
                message_id.get("value"), 
                "suspicious", 
                "Domain doesn't match sender domain"
            )
    
    def _evaluate_content_rules(self, extracted_attributes: Dict) -> None:
        """
        Evaluate content-related security indicators.
        
        Args:
            extracted_attributes: Dictionary containing extracted email header attributes
        """
        content = extracted_attributes.get("content", {})
        
        # Check for unusual encoding
        if content.get("unusual_encoding"):
            self._add_indicator(
                "unusual_content_encoding",
                "Unusual content encoding",
                f"Encoding: {content.get('transfer_encoding')}"
            )
            
            # Add to header analysis
            self._add_header_evaluation(
                "content-transfer-encoding", 
                content.get("transfer_encoding"), 
                "suspicious", 
                "Unusual content encoding"
            )
    
    def _add_indicator(self, rule_name: str, name: str, description: str) -> None:
        """
        Record a security indicator in the evaluation results.
        
        Args:
            rule_name: Internal rule identifier matching SECURITY_RULE_SCORES keys
            name: Human-readable security indicator name
            description: Detailed explanation of the security indicator
        """
        self.triggered_rules.append({
            "rule": rule_name,
            "name": name,
            "description": description,
            "weight": SECURITY_RULE_SCORES.get(rule_name, 10)  # Default weight if rule not defined
        })
    
    def _add_header_evaluation(self, header: str, value: str, status: str, reason: str = "") -> None:
        """
        Record header evaluation information in the results.
        
        Args:
            header: Header field name
            value: Header field value
            status: Evaluation status ("safe", "suspicious", "neutral")
            reason: Explanation for the evaluation status
        """
        self.header_evaluation[header] = {
            "value": value,
            "status": status,
            "reason": reason
        }
    
    def _compute_risk_score(self) -> float:
        """
        Compute the security risk probability score based on triggered security rules.
        
        Returns:
            Risk score between 0 and 100
        """
        if not self.triggered_rules:
            return 0.0
        
        # Sum the scores of all triggered security rules
        total_score = sum(rule.get("weight", 10) for rule in self.triggered_rules)
        
        # Compute final score (capped at 100)
        risk_score = min(total_score, 100)
        
        return risk_score


if __name__ == "__main__":
    # Test script when executed directly
    import sys
    import json
    from email_parser import EmailHeaderAnalyzer
    from feature_extractor import EmailAttributeExtractor
    
    if len(sys.argv) > 1:
        analyzer = EmailHeaderAnalyzer(sys.argv[1])
        parsed_content = analyzer.process_email()
        
        extractor = EmailAttributeExtractor(parsed_content)
        extracted_attributes = extractor.collect_header_attributes()
        
        evaluator = SuspiciousEmailDetector(verbose=True)
        evaluation_result = evaluator.evaluate_email(extracted_attributes)
        
        print(f"Phishing probability: {evaluation_result['phishing_probability']}%")
        print(f"Verdict: {'POTENTIAL PHISHING' if evaluation_result['is_phishing'] else 'LIKELY LEGITIMATE'}")
        
        if evaluation_result["indicators"]:
            print("\nSuspicious indicators:")
            for indicator in evaluation_result["indicators"]:
                print(f" - {indicator['name']}: {indicator['description']}")
    else:
        print("Please provide an email file path as argument")