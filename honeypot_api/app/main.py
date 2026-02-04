import os
import json
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from honeypot_api.app.detector import detect_scam
from honeypot_api.app.extractor import extract_intelligence
from honeypot_api.app.memory import update_conversation, get_metrics
from honeypot_api.app.models import HoneypotResponse

app = FastAPI(title="Buildathon Honeypot API")

# Use your AlzaSy... key in Render Environment Variables
API_KEY = os.getenv("API_KEY", "changeme")

@app.get("/")
async def root():
    return {"status": "online", "message": "Honeypot API is live."}

@app.post("/honeypot", response_model=HoneypotResponse)
async def honeypot(request: Request):
    # 1. Manual Header Check
    x_api_key = request.headers.get("x-api-key")
    if x_api_key != API_KEY:
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

    # 2. DEFENSIVE PARSING: Read raw body to prevent 422 errors
    raw_data = await request.body()
    try:
        body = json.loads(raw_data) if raw_data else {}
        if not isinstance(body, dict):
            body = {}
    except Exception:
        body = {}

    # 3. SAFE DEFAULTS: Use .get() to prevent KeyErrors
    message = str(body.get("message", ""))
    conversation_id = str(body.get("conversation_id", "default"))

    # 4. LOGIC EXECUTION
    try:
        scam_detected = detect_scam(message)
        extracted = extract_intelligence(message)
        update_conversation(conversation_id)
        turns, duration = get_metrics(conversation_id)
    except Exception:
        # Final fallback if internal logic fails
        scam_detected, turns, duration = False, 1, 0
        extracted = {"bank_accounts": [], "upi_ids": [], "phishing_links": []}

    # 5. GUARANTEED 200 OK RESPONSE
    return {
        "scam_detected": bool(scam_detected),
        "engagement_metrics": {
            "conversation_turns": int(turns),
            "engagement_duration_seconds": int(duration)
        },
        "extracted_intelligence": extracted
    }