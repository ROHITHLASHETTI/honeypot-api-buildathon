import re

def extract_intelligence(message: str):
    # Patterns to catch the scammer's infrastructure
    bank_pattern = r"\b\d{9,18}\b"
    upi_pattern = r"\b[\w.-]+@[\w.-]+\b"
    url_pattern = r"https?://[^\s]+"

    return {
        "bank_accounts": [{"account_number": acc} for acc in re.findall(bank_pattern, message)],
        "upi_ids": re.findall(upi_pattern, message),
        "phishing_links": re.findall(url_pattern, message)
    }