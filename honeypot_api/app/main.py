import os
from fastapi import FastAPI, Header, HTTPException, Request

from honeypot_api.app.detector import detect_scam
from honeypot_api.app.extractor import extract_intelligence
from honeypot_api.app.memory import update_conversation, get_metrics

app = FastAPI()

API_KEY = os.getenv("API_KEY", "changeme")

@app.post("/honeypot")
async def honeypot(
    request: Request,
    x_api_key: str = Header(None)
):
    # API key validation
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Safely read JSON body (even if empty)
    try:
        body = await request.json()
    except Exception:
        body = {}

    conversation_id = body.get("conversation_id", "default")
    message = body.get("message", "")

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
