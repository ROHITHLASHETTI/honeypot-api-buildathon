import re

def extract_intelligence(message: str):
    if not message:
        return {
            "bank_accounts": [],
            "upi_ids": [],
            "phishing_links": []
        }

    BANK_REGEX = r"\b\d{9,18}\b"
    UPI_REGEX = r"\b[\w.-]+@[\w.-]+\b"
    URL_REGEX = r"https?://[^\s]+"

    return {
        "bank_accounts": [{"account_number": acc, "ifsc": None} for acc in re.findall(BANK_REGEX, message)],
        "upi_ids": re.findall(UPI_REGEX, message),
        "phishing_links": re.findall(URL_REGEX, message)
    }