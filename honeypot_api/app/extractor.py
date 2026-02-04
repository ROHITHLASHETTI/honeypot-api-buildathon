import re

BANK_REGEX = r"\b\d{9,18}\b"
IFSC_REGEX = r"\b[A-Z]{4}0[A-Z0-9]{6}\b"
UPI_REGEX = r"\b[\w.-]+@[\w.-]+\b"
URL_REGEX = r"https?://[^\s]+"

def extract_intelligence(message: str):
    banks = []
    for acc in re.findall(BANK_REGEX, message):
        banks.append({"account_number": acc, "ifsc": None})

    return {
        "bank_accounts": banks,
        "upi_ids": re.findall(UPI_REGEX, message),
        "phishing_links": re.findall(URL_REGEX, message)
    }
