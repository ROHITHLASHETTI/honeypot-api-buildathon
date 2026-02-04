import re

def detect_scam(message: str) -> bool:
    if not message:
        return False
    
    # Keywords often found in scam messages
    scam_keywords = [
        r"urgent", r"locked", r"win", r"prize", r"lottery", 
        r"bank details", r"verify", r"account suspended", r"pay now"
    ]
    
    message_lower = message.lower()
    for pattern in scam_keywords:
        if re.search(pattern, message_lower):
            return True
            
    # Also flag if it contains a UPI ID or multiple numbers
    if "@" in message or len(re.findall(r"\d", message)) > 10:
        return True
        
    return False