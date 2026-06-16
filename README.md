Project Objectives

The primary objectives of this project are:

Detect common phishing indicators in messages and emails
Analyze URLs for suspicious characteristics
Inspect sender email addresses
Identify domain impersonation attempts
Calculate a phishing risk score
Classify content based on risk level
Provide a user-friendly graphical interface
Features
URL Analysis
HTTPS verification
IP-based URL detection
URL shortening service detection
Long URL identification
Excessive subdomain detection
Email Analysis
Sender email extraction
Domain validation
Trusted domain comparison
Suspicious sender identification
Domain Similarity Detection
Detection of lookalike domains
Identification of possible brand impersonation
Comparison against known trusted domains
Content Analysis
Suspicious keyword detection
Urgency analysis
Password request identification
Account verification request detection
Risk Assessment
Risk score calculation
Detailed detection explanations
Safe / Suspicious / High-Risk classification
Technologies Used
Technology	Purpose
Python	Core application development
Tkinter	Desktop graphical user interface
Regular Expressions (Regex)	Pattern matching and extraction
urllib.parse	URL parsing and validation
difflib	Domain similarity detection
Application Workflow
User enters an email, message, or URL.
The application extracts URLs and email addresses.
URLs are analyzed for suspicious indicators.
Sender domains are inspected for legitimacy.
Message content is analyzed for phishing-related language.
A risk score is generated.
The content is classified as:
Safe
Suspicious
High Risk
Example Detection
Sample Input

From: support@paypa1-security.com

URGENT!

We detected unusual activity on your PayPal account.

Please verify your password immediately:

http://paypa1-security-login.com/verify/account

Act now to avoid suspension.

Detection Result

Verdict: PHISHING / HIGH RISK

Risk Score: 15

Indicators Detected:

Suspicious keywords
Urgent language
Password request
Insecure HTTP connection
Suspicious domain structure

High-Risk Phishing Detection

The application successfully identifies a phishing message and provides a detailed explanation of the detected indicators.

Safe Message Detection

The application correctly classifies legitimate content as low risk when no phishing indicators are detected.

Future Improvements
Machine Learning-based classification
VirusTotal API integration
WHOIS domain analysis
Email header inspection
Threat intelligence integration
Domain reputation scoring
Export reports to PDF
Database logging and analytics
Skills Demonstrated

This project demonstrates practical experience in:

Cybersecurity Analysis
Phishing Detection
Python Programming
Secure Software Development
GUI Development
Threat Assessment
Pattern Recognition
Security Automation

Author
Sultan Titilayo
