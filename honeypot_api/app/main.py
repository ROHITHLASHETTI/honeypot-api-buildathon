import os
from fastapi import FastAPI, Header, HTTPException
from app.models import HoneypotRequest, HoneypotResponse
from app.detector import detect_scam
from app.extractor import extract_intelligence
from app.memory import update_conversation, get_metrics

app = FastAPI()

API_KEY = os.getenv("API_KEY", "changeme")

@app.post("/honeypot", response_model=HoneypotResponse)
def honeypot(
    request: HoneypotRequest,
    x_api_key: str = Header(None)
):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    update_conversation(request.conversation_id)

    scam_detected = detect_scam(request.message)
    extracted = extract_intelligence(request.message)

    turns, duration = get_metrics(request.conversation_id)

    return {
        "scam_detected": scam_detected,
        "engagement_metrics": {
            "conversation_turns": turns,
            "engagement_duration_seconds": duration
        },
        "extracted_intelligence": extracted
    }
