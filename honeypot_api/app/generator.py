def generate_honeypot_reply(scammer_message: str) -> str:
    # This acts as the 'trapping' logic
    # In a full version, you'd call Gemini API here
    prompts = [
        "Oh dear, I'm not very good with phones. How do I fix my account?",
        "Is my money safe? Should I send it to that UPI ID you mentioned?",
        "I'm worried! Do I need to click that link right now?",
        "I have my checkbook ready, what details do you need?"
    ]
    import random
    return random.choice(prompts)