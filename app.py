#!/usr/bin/env python3
"""
Email Security Evaluation Web Interface

This script provides a web interface for the email security evaluation system,
allowing users to upload email files and view security assessment evaluation_results.
"""

import os
import json
import re
import html
from datetime import datetime
from pathlib import Path
from flask import Flask, request, render_template, jsonify, redirect, url_for, flash
from werkzeug.utils import secure_filename

# Import local modules
from email_parser import EmailHeaderAnalyzer
from feature_extractor import EmailAttributeExtractor
from detection_rules import SuspiciousEmailDetector
from utils import setup_logger

# Setup logger
logger = setup_logger()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configure upload settings
UPLOAD_FOLDER = Path('uploads')
ALLOWED_EXTENSIONS = {'eml', 'msg', 'txt'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size

# Create upload directory if it doesn't exist
if not UPLOAD_FOLDER.exists():
    UPLOAD_FOLDER.mkdir(parents=True)

# Initialize security evaluator
evaluator = SuspiciousEmailDetector()


def allowed_file(filename):
    """Check if the file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def sanitize_html_for_display(html_content):
    """
    Sanitize HTML content for safe display in the browser.
    Removes dangerous elements but keeps basic formatting.
    """
    if not html_content:
        return ""
    
    # Remove script tags and their content
    html_content = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
    
    # Remove dangerous attributes like onclick, onload, etc.
    html_content = re.sub(r'\s+on\w+\s*=\s*["\'][^"\']*["\']', '', html_content, flags=re.IGNORECASE)
    
    # Remove javascript: links
    html_content = re.sub(r'href\s*=\s*["\']javascript:[^"\']*["\']', 'href="#"', html_content, flags=re.IGNORECASE)
    
    # Remove style tags (but keep inline styles for basic formatting)
    html_content = re.sub(r'<style[^>]*>.*?</style>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
    
    return html_content


def html_to_text(html_content):
    """Convert HTML content to plain text by stripping tags"""
    if not html_content:
        return ""
    
    # Remove all HTML tags
    text = re.sub(r'<[^>]+>', '', html_content)
    
    # Decode HTML entities
    text = html.unescape(text)
    
    # Clean up whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    
    return text


@app.route('/')
def index():
    """Render the main page"""
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and analysis"""
    # Check if a file was uploaded
    if 'file' not in request.files:
        flash('No file part', 'error')
        return redirect(request.url)
    
    file = request.files['file']
    
    # Check if a file was selected
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(request.url)
    
    # Check if the file type is allowed
    if file and allowed_file(file.filename):
        # Save the file
        filename = secure_filename(file.filename)
        file_path = UPLOAD_FOLDER / filename
        file.save(file_path)
        
        # Analyze the email
        try:
            # Parse email
            analyzer = EmailHeaderAnalyzer(str(file_path))
            parsed_content = analyzer.process_email()
            
            if not parsed_content:
                flash('Failed to parse email file', 'error')
                return redirect(url_for('index'))
            
            # Collect header attributes
            extractor = EmailAttributeExtractor(parsed_content)
            extracted_attributes = extractor.collect_header_attributes()
            
            # Evaluate email security
            evaluation_result = evaluator.evaluate_email(extracted_attributes)
            evaluation_result["file"] = filename
            evaluation_result["analysis_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Store evaluation_result in session for display
            return redirect(url_for('evaluation_result', analysis_id=filename))
            
        except Exception as e:
            logger.error(f"Error analyzing {filename}: {str(e)}")
            flash(f'Error analyzing file: {str(e)}', 'error')
            return redirect(url_for('index'))
    else:
        flash(f'Invalid file type. Allowed types: {", ".join(ALLOWED_EXTENSIONS)}', 'error')
        return redirect(url_for('index'))


@app.route('/evaluation_result/<analysis_id>')
def evaluation_result(analysis_id):
    """Display analysis evaluation_result"""
    # Get the file path
    file_path = UPLOAD_FOLDER / secure_filename(analysis_id)
    
    if not file_path.exists():
        flash('Analysis not found', 'error')
        return redirect(url_for('index'))
    
    try:
        # Re-analyze the email to get fresh evaluation_results
        analyzer = EmailHeaderAnalyzer(str(file_path))
        parsed_content = analyzer.process_email()
        
        if not parsed_content:
            flash('Failed to parse email file', 'error')
            return redirect(url_for('index'))
        
        # Collect header attributes
        extractor = EmailAttributeExtractor(parsed_content)
        extracted_attributes = extractor.collect_header_attributes()
        
        # Evaluate email security
        evaluation_result = evaluator.evaluate_email(extracted_attributes)
        evaluation_result["file"] = analysis_id
        evaluation_result["analysis_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Add email metadata for display
        headers = parsed_content.get("headers", {})
        evaluation_result["email_metadata"] = {
            "from": headers.get("from", "Unknown"),
            "to": headers.get("to", "Unknown"),
            "subject": headers.get("subject", "Unknown"),
            "date": headers.get("date", "Unknown"),
        }
        
        # Add features for template compatibility
        body_html = parsed_content.get("body_html", "")
        body_plain = parsed_content.get("body_plain", "")
        body_generic = parsed_content.get("body", "")
        
        # Format headers for better display
        formatted_headers = []
        for key, value in headers.items():
            # Clean up header names and values
            clean_key = key.title().replace('-', ' ')
            clean_value = str(value).strip() if value else ""
            
            # Replace newlines with proper HTML line breaks and clean up whitespace
            import re
            # First normalize whitespace within lines
            clean_value = re.sub(r'[ \t]+', ' ', clean_value)
            # Then replace newlines with <br> and remove excessive line breaks
            clean_value = clean_value.replace('\n', '<br>').replace('\r', '')
            # Clean up multiple consecutive <br> tags
            clean_value = re.sub(r'(<br>\s*){3,}', '<br><br>', clean_value)
            clean_value = clean_value.strip()
            
            # Truncate very long values for display
            if len(clean_value.replace('<br>', '\n')) > 200:
                clean_value = clean_value[:200] + "..."
            formatted_headers.append({"name": clean_key, "value": clean_value})
        
        # Determine what to show in the body tab
        if body_html:
            # Sanitize HTML for display
            sanitized_html = sanitize_html_for_display(body_html)
            evaluation_result["features"] = {
                "body": body_plain if body_plain else html_to_text(body_html),  # Plain text version
                "body_html": sanitized_html,  # Sanitized HTML version
                "raw_headers": "\n".join([f"{k}: {v}" for k, v in headers.items()]),
                "formatted_headers": formatted_headers,
                "attachments": parsed_content.get("attachments", [])
            }
        else:
            # Plain text or generic content
            evaluation_result["features"] = {
                "body": body_plain or body_generic,
                "body_html": None,
                "raw_headers": "\n".join([f"{k}: {v}" for k, v in headers.items()]),
                "formatted_headers": formatted_headers,
                "attachments": parsed_content.get("attachments", [])
            }
        
        return render_template('result.html', result=evaluation_result)
        
    except Exception as e:
        logger.error(f"Error displaying evaluation_results for {analysis_id}: {str(e)}")
        flash(f'Error displaying evaluation_results: {str(e)}', 'error')
        return redirect(url_for('index'))


@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """API endpoint for email analysis"""
    # Check if a file was uploaded
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "No file part"}), 400
    
    file = request.files['file']
    
    # Check if a file was selected
    if file.filename == '':
        return jsonify({"status": "error", "message": "No selected file"}), 400
    
    # Check if the file type is allowed
    if file and allowed_file(file.filename):
        # Save the file
        filename = secure_filename(file.filename)
        file_path = UPLOAD_FOLDER / filename
        file.save(file_path)
        
        # Analyze the email
        try:
            # Parse email
            analyzer = EmailHeaderAnalyzer(str(file_path))
            parsed_content = analyzer.process_email()
            
            if not parsed_content:
                return jsonify({"status": "error", "message": "Failed to parse email file"}), 400
            
            # Collect header attributes
            extractor = EmailAttributeExtractor(parsed_content)
            extracted_attributes = extractor.collect_header_attributes()
            
            # Evaluate email security
            evaluation_result = evaluator.evaluate_email(extracted_attributes)
            evaluation_result["file"] = filename
            evaluation_result["analysis_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            return jsonify({"status": "success", "evaluation_result": evaluation_result})
            
        except Exception as e:
            logger.error(f"API Error analyzing {filename}: {str(e)}")
            return jsonify({"status": "error", "message": str(e)}), 500
    else:
        return jsonify({"status": "error", "message": f"Invalid file type. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}"}), 400


@app.route('/dashboard')
def dashboard():
    """Display dashboard with statistics"""
    # Get all analyzed files
    analyzed_files = list(UPLOAD_FOLDER.glob('*'))
    
    # Initialize statistics
    stats = {
        'total_analyzed': len(analyzed_files),
        'phishing_detected': 0,
        'legitimate': 0,
        'detection_rate': 0,
        'recent_analyses': [],
        'monthly_data': {},
        'top_indicators': []
    }
    
    # Initialize indicators tracking
    indicators = {}
    domains = {}
    timeline_data = {}
    
    # Process each analyzed file
    for file_path in analyzed_files:
        try:
            # Parse email
            analyzer = EmailHeaderAnalyzer(str(file_path))
            parsed_content = analyzer.process_email()
            
            if not parsed_content:
                continue
            
            # Collect header attributes
            extractor = EmailAttributeExtractor(parsed_content)
            extracted_attributes = extractor.collect_header_attributes()
            
            # Evaluate email security
            evaluation_result = evaluator.evaluate_email(extracted_attributes)
            
            # Update statistics
            if evaluation_result['is_phishing']:
                stats['phishing_detected'] += 1
            else:
                stats['legitimate'] += 1
            
            # Track indicators
            for indicator in evaluation_result['indicators']:
                if indicator['name'] not in indicators:
                    indicators[indicator['name']] = 0
                indicators[indicator['name']] += 1
            
            # Track domains
            headers = parsed_content.get("headers", {})
            from_header = headers.get("from", "")
            sender_domain = from_header.split('@')[-1] if '@' in from_header else 'unknown'
            # Extract just the domain part if there's a name before email
            if '<' in sender_domain:
                sender_domain = sender_domain.split('<')[-1].split('>')[0].split('@')[-1] if '@' in sender_domain else 'unknown'
            if sender_domain not in domains:
                domains[sender_domain] = {'count': 0, 'phishing': 0}
            domains[sender_domain]['count'] += 1
            if evaluation_result['is_phishing']:
                domains[sender_domain]['phishing'] += 1
            
            # Track timeline data
            analysis_date = datetime.fromtimestamp(file_path.stat().st_mtime).strftime('%Y-%m-%d')
            analysis_month = datetime.fromtimestamp(file_path.stat().st_mtime).strftime('%Y-%m')
            if analysis_date not in timeline_data:
                timeline_data[analysis_date] = {'total': 0, 'phishing': 0}
            timeline_data[analysis_date]['total'] += 1
            if evaluation_result['is_phishing']:
                timeline_data[analysis_date]['phishing'] += 1
                
            # Track monthly data for trends chart
            if analysis_month not in stats['monthly_data']:
                stats['monthly_data'][analysis_month] = {'phishing': 0, 'legitimate': 0}
            if evaluation_result['is_phishing']:
                stats['monthly_data'][analysis_month]['phishing'] += 1
            else:
                stats['monthly_data'][analysis_month]['legitimate'] += 1
            
            # Add to recent analyses
            stats['recent_analyses'].append({
                'file': file_path.name,
                'date': datetime.fromtimestamp(file_path.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                'is_phishing': evaluation_result['is_phishing'],
                'score': evaluation_result.get('phishing_probability', evaluation_result.get('phishing_score', 0))
            })
                
        except Exception as e:
            logger.error(f"Error processing {file_path.name} for dashboard: {str(e)}")
    
    # Calculate detection rate
    if stats['total_analyzed'] > 0:
        stats['detection_rate'] = round((stats['phishing_detected'] / stats['total_analyzed']) * 100, 1)
    
    # Sort indicators by frequency
    sorted_indicators = [{'name': k, 'count': v} for k, v in sorted(indicators.items(), key=lambda item: item[1], reverse=True)]
    
    # Sort domains by phishing count
    sorted_domains = [{'name': k, 'count': v['count'], 'phishing': v['phishing']} 
                     for k, v in sorted(domains.items(), key=lambda item: item[1]['phishing'], reverse=True)]
    
    # Prepare timeline data for chart
    if timeline_data:
        timeline_labels = sorted(timeline_data.keys())
        timeline_values = {
            'total': [timeline_data[date]['total'] for date in timeline_labels],
            'phishing': [timeline_data[date]['phishing'] for date in timeline_labels]
        }
    else:
        # Fallback if no timeline data available
        timeline_labels = []
        timeline_values = {'total': [], 'phishing': []}
    
    # Sort recent analyses by date (newest first) and limit to 5
    stats['recent_analyses'] = sorted(
        stats['recent_analyses'],
        key=lambda x: x['date'],
        reverse=True
    )[:5]
    
    # Prepare monthly data for trends chart
    month_labels = []
    phishing_counts = []
    legitimate_counts = []
    
    # If we have actual data, use it
    if stats['monthly_data']:
        # Get the last 6 months (or all if less than 6)
        sorted_months = sorted(stats['monthly_data'].keys())[-6:]
        for month in sorted_months:
            month_labels.append(datetime.strptime(month, '%Y-%m').strftime('%b'))
            phishing_counts.append(stats['monthly_data'][month]['phishing'])
            legitimate_counts.append(stats['monthly_data'][month]['legitimate'])
    else:
        # Fallback to empty data if no monthly stats available
        month_labels = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun']
        phishing_counts = [0, 0, 0, 0, 0, 0]
        legitimate_counts = [0, 0, 0, 0, 0, 0]

    # Add top indicators to stats
    stats['top_indicators'] = sorted_indicators[:5]  # Top 5 indicators
    
    return render_template('dashboard.html', 
                           stats=stats, 
                           indicators=sorted_indicators[:10],  # Top 10 indicators
                           domains=sorted_domains[:10],       # Top 10 domains
                           timeline_labels=timeline_labels,
                           timeline_values=timeline_values,
                           month_labels=month_labels,
                           phishing_counts=phishing_counts,
                           legitimate_counts=legitimate_counts)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)