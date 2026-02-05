import re

def extract_intelligence(message: str):
    # Retrieve Bank Accounts (9-18 digits)
    bank_pattern = r"\b\d{9,18}\b"
    # Retrieve UPI IDs
    upi_pattern = r"\b[\w.-]+@[\w.-]+\b"
    # Retrieve Phishing Links
    url_pattern = r"https?://[^\s]+"

    return {
        "bank_accounts": [{"account_number": acc} for acc in re.findall(bank_pattern, message)],
        "upi_ids": re.findall(upi_pattern, message),
        "phishing_links": re.findall(url_pattern, message)
    }