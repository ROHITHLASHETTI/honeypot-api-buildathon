import re

def detect_scam(message: str) -> bool:
    if not message: return False
    
    keywords = [r"urgent", r"locked", r"pay", r"bank", r"win", r"prize"]
    msg_lower = message.lower()
    
    # Flag if keywords found OR if it looks like a UPI/Bank request
    if any(re.search(k, msg_lower) for k in keywords): return True
    if "@" in message or re.search(r"\d{10,}", message): return True
    
    return False