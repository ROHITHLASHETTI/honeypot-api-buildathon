import re

def detect_scam(message: str) -> bool:
    if not message: return False
    keywords = [r"urgent", r"blocked", r"pay", r"bank", r"win", r"otp", r"sbi", r"kyc"]
    msg_lower = message.lower()
    return any(re.search(k, msg_lower) for k in keywords) or "@" in message