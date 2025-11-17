# Sample Email Data

This directory contains sample email files for testing the phishing detection system.

## Directory Structure

- `legitimate/`: Contains legitimate email samples
- `phishing/`: Contains phishing email samples

## Adding Your Own Samples

You can add your own email samples to these directories for testing. The system supports the following email formats:

- `.eml`: Standard email format
- `.msg`: Microsoft Outlook email format (requires mailparser library)
- `.txt`: Plain text email format

## Sample Sources

For real-world testing, you can obtain email samples from the following sources:

1. **Enron Email Dataset**: A large dataset of legitimate emails
   - Available at: https://www.cs.cmu.edu/~enron/

2. **Phishing Email Datasets on Kaggle**:
   - https://www.kaggle.com/datasets/subhajournal/phishingemails
   - https://www.kaggle.com/datasets/rtatman/fraudulent-email-corpus

3. **PhishTank**: Database of verified phishing emails
   - https://phishtank.org/

## Privacy Note

When adding your own email samples, make sure to remove or anonymize any personal or sensitive information.