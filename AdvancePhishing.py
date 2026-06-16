import tkinter as tk
from tkinter import messagebox
import re
import urllib.parse
import difflib


TRUSTED_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "paypal.com",
    "amazon.com", "facebook.com", "instagram.com", "linkedin.com",
    "github.com", "python.org", "chase.com", "bankofamerica.com"
]

SUSPICIOUS_KEYWORDS = [
    "verify", "password", "urgent", "suspended", "locked",
    "confirm", "payment", "click here", "act now", "limited",
    "winner", "prize", "free", "security alert", "unusual activity"
]

SHORTENER = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "cutt.ly", "is.gd", "buff.ly", "rebrand.ly"
]


def extract_urls(text):
    return re.findall(r"https?://[^\s']+|www\.[^\s']+", text)


def extract_emails(text):
    return re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", text)


def normalize_url(url):
    if url.startswith("www."):
        return "HTTP://" + url
    return url


def get_domain(url):
    parsed = urllib.parse.urlparse(normalize_url(url))
    domain = parsed.netloc.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def is_ip_address(domain):
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain))


def check_lookalike_domain(domain):
    findings = []

    for trusted in TRUSTED_DOMAINS:
        similarity = difflib.SequenceMatcher(None, domain, trusted).ratio()

        if similarity > 0.75 and domain != trusted and not domain.endswith("." + trusted):
            findings.append(f"Possible lookalike domain: {domain} looks like {trusted}")

    return findings


def check_url(url):
    score = 0
    reasons = []

    url = normalize_url(url)
    parsed = urllib.parse.urlparse(url)
    domain = get_domain(url)
    full_url = url.lower()

    if parsed.scheme != "https":
        score += 2
        reasons.append("URL does not use HTTPS")

    if "@" in url:
        score += 4
        reasons.append("URL contains @ symbol")

    if "-" in domain:
        score += 1
        reasons.append("Domain contains hyphen")

    if domain.count(".") >= 3:
        score += 2
        reasons.append("URL has many subdomains")

    if len(url) > 90:
        score += 2
        reasons.append("URL is very long")

    if any(shortener in domain for shortener in SHORTENER):
        score += 4
        reasons.append("URL uses a link shortener")

    if is_ip_address(domain):
        score += 4
        reasons.append("URL uses an IP address instead of a domain name")

    for word in SUSPICIOUS_KEYWORDS:
        if word in full_url:
            score += 1
            reasons.append(f"Suspicious word in URL: {word}")

    lookalike_findings = check_lookalike_domain(domain)
    if lookalike_findings:
        score += 5
        reasons.extend(lookalike_findings)

    if domain in TRUSTED_DOMAINS or any(domain.endswith("." + d) for d in TRUSTED_DOMAINS):
        score -= 2
        reasons.append("Domain appears in trusted domain list")

    return max(score, 0), reasons


def check_email_sender(email):
    score = 0
    reasons = []

    domain = email.split("@")[-1].lower()

    if domain not in TRUSTED_DOMAINS:
        score += 1
        reasons.append(f"Sender domain is not in trusted list: {domain}")

    lookalike_findings = check_lookalike_domain(domain)
    if lookalike_findings:
        score += 5
        reasons.extend(lookalike_findings)

    if "-" in domain:
        score += 1
        reasons.append("Sender domain contains hyphen")

    return score, reasons


def check_message_text(text):
    score = 0
    reasons = []
    lower_text = text.lower()

    for word in SUSPICIOUS_KEYWORDS:
        if word in lower_text:
            score += 1
            reasons.append(f"Suspicious phrase found: {word}")

    if "verify your account" in lower_text:
        score += 3
        reasons.append("Message asks user to verify account")

    if "enter your password" in lower_text or "password" in lower_text:
        score += 2
        reasons.append("Message mentions password")

    if "urgent" in lower_text or "act now" in lower_text:
        score += 2
        reasons.append("Message creates urgency")

    return score, reasons


def get_verdict(score):
    if score >= 15:
        return "PHISHING / HIGH RISK"
    elif score >= 7:
        return "SUSPICIOUS / MEDIUM RISK"
    else:
        return "SAFE / LOW RISK"


def scan_text():
    text = input_box.get("1.0", tk.END).strip()

    if not text:
        messagebox.showwarning("Warning", "Please enter a URL, email, or message.")
        return

    total_score = 0
    reasons = []

    text_score, text_reasons = check_message_text(text)
    total_score += text_score
    reasons.extend(text_reasons)

    urls = extract_urls(text)
    emails = extract_emails(text)

    for url in urls:
        url_score, url_reasons = check_url(url)
        total_score += url_score
        reasons.append(f"Checked URL: {url}")
        reasons.extend(url_reasons)

    for email in emails:
        email_score, email_reasons = check_email_sender(email)
        total_score += email_score
        reasons.append(f"Checked sender/email: {email}")
        reasons.extend(email_reasons)

    verdict = get_verdict(total_score)

    result_box.delete("1.0", tk.END)
    result_box.insert(tk.END, "===== PHISHING DETECTION RESULT =====\n\n")
    result_box.insert(tk.END, f"Verdict: {verdict}\n")
    result_box.insert(tk.END, f"Risk Score: {total_score}\n")
    result_box.insert(tk.END, f"URLs Found: {len(urls)}\n")
    result_box.insert(tk.END, f"Emails Found: {len(emails)}\n\n")

    result_box.insert(tk.END, "Reasons:\n")

    if reasons:
        for reason in reasons:
            result_box.insert(tk.END, f"- {reason}\n")
    else:
        result_box.insert(tk.END, "- No suspicious indicators found.\n")


def clear_all():
    input_box.delete("1.0", tk.END)
    result_box.delete("1.0", tk.END)


app = tk.Tk()
app.title("Intermediate Phishing Detection Tool")
app.geometry("850x650")

title = tk.Label(
    app,
    text="Phishing Detection Tool",
    font=("Arial", 22, "bold")
)
title.pack(pady=10)

subtitle = tk.Label(
    app,
    text="Paste an email, message, sender address, or URL to scan",
    font=("Arial", 11)
)
subtitle.pack()

input_box = tk.Text(app, height=12, width=95)
input_box.pack(pady=10)

button_frame = tk.Frame(app)
button_frame.pack(pady=5)

scan_button = tk.Button(
    button_frame,
    text="Scan",
    width=18,
    command=scan_text
)
scan_button.grid(row=0, column=0, padx=10)

clear_button = tk.Button(
    button_frame,
    text="Clear",
    width=18,
    command=clear_all
)
clear_button.grid(row=0, column=1, padx=10)

result_label = tk.Label(
    app,
    text="Scan Result",
    font=("Arial", 14, "bold")
)
result_label.pack(pady=5)

result_box = tk.Text(app, height=18, width=95)
result_box.pack(pady=10)

footer = tk.Label(
    app,
    text="Built with Python Tkinter | Rule-Based Phishing Detection",
    font=("Arial", 9)
)
footer.pack(pady=5)

app.mainloop()