# Phishing Detection System Web Interface

This web interface provides a user-friendly way to interact with the Phishing Detection System, allowing users to upload email files for analysis and view detailed results.

## Features

- **Email Upload**: Easily upload email files (.eml, .msg, .txt) for analysis
- **Detailed Results**: View comprehensive analysis results with suspicious indicators highlighted
- **Dashboard**: Access statistics and trends about analyzed emails
- **Responsive Design**: Works on desktop and mobile devices

## Setup and Installation

1. Make sure you have all the required dependencies installed:

```bash
pip install -r requirements.txt
```

2. Run the web application:

```bash
python app.py
```

3. Open your browser and navigate to http://localhost:5000

## Usage

1. **Home Page**: Upload email files for analysis
2. **Results Page**: View detailed analysis of the uploaded email
3. **Dashboard**: View statistics and trends

## API Endpoints

The system also provides a simple API for programmatic access:

- `POST /api/analyze`: Upload an email file for analysis
  - Request: multipart/form-data with a file field named 'file'
  - Response: JSON with analysis results

## Directory Structure

```
├── app.py                # Main Flask application
├── templates/            # HTML templates
│   ├── index.html        # Home page
│   ├── result.html       # Results page
│   └── dashboard.html    # Dashboard page
├── static/               # Static assets
│   ├── css/              # CSS stylesheets
│   └── js/               # JavaScript files
└── uploads/              # Directory for uploaded files
```

## Integration with Core System

The web interface integrates with the core phishing detection system, using the following components:

- `email_parser.py`: For parsing uploaded email files
- `feature_extractor.py`: For extracting features from emails
- `detection_rules.py`: For analyzing emails and detecting phishing attempts

## Future Improvements

- User authentication and management
- Email history and saved results
- Advanced filtering and search capabilities
- Real-time email scanning integration
- Machine learning model integration