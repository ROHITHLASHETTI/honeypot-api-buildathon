import os
from fastapi import FastAPI, Header, HTTPException

from honeypot_api.app.models import HoneypotRequest, HoneypotResponse
from honeypot_api.app.detector import detect_scam
from honeypot_api.app.extractor import extract_intelligence
from honeypot_api.app.memory import update_conversation, get_metrics

app = FastAPI()

API_KEY = os.getenv("API_KEY", "changeme")

@app.post("/honeypot", response_model=HoneypotResponse)
def honeypot(
    request: HoneypotRequest,
    x_api_key: str = Header(None)
):
    # API key validation
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Make request safe (prevents 422)
    conversation_id = request.conversation_id or "default"
    message = request.message or ""

    update_conversation(conversation_id)

    scam_detected = detect_scam(message)
    extracted = extract_intelligence(message)

    turns, duration = get_metrics(conversation_id)

    return {
        "scam_detected": scam_detected,
        "engagement_metrics": {
            "conversation_turns": turns,
            "engagement_duration_seconds": duration
        },
        "extracted_intelligence": extracted
    }
