# Email Phishing Analyzer

A Python-based cybersecurity project that analyzes email headers and message content to identify potential phishing attacks and email spoofing attempts.

## Features

- Parses email headers, including Received and Return-Path.
- Checks reported SPF, DKIM, and DMARC authentication results.
- Detects suspicious links and possible domain spoofing.
- Identifies urgent and threatening language.
- Calculates a phishing risk score from 0 to 100.
- Generates an email security audit report in JSON format.

## Technologies Used

- Python 3
- Python Standard Library
- Email Header Parsing
- Regular Expressions
- JSON

## How to Run

1. Download or clone the repository.
2. Open the project folder in VS Code.
3. Run the following command:

```bash
python email_analyzer.py sample_suspicious.eml


## Output

The analyzer displays the phishing risk score and detected security indicators. It also saves the results to `audit_report.json`.

## Project Files

- `email_analyzer.py` — Main Python script
- `sample_suspicious.eml` — Sample phishing email
- `sample_audit.json` — Sample analysis results
- `Phishing_Analysis_Report.pdf` — Project documentation and analysis report

## Disclaimer

This project is for educational and defensive cybersecurity purposes. Authentication results are read from email headers and are not independently verified. Risk scores are heuristic estimates, not definitive proof of phishing.