SCAM_KEYWORDS = [
    "blocked", "verify", "urgent", "refund",
    "click", "link", "account", "payment"
]

def detect_scam(message: str) -> bool:
    msg = message.lower()
    return any(word in msg for word in SCAM_KEYWORDS)
