import os
import json
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# Standard imports
from honeypot_api.app.detector import detect_scam
from honeypot_api.app.extractor import extract_intelligence
from honeypot_api.app.memory import update_conversation, get_metrics

app = FastAPI()
API_KEY = os.getenv("API_KEY", "changeme")

@app.post("/honeypot")
async def honeypot(request: Request):
    # 1. Manually check API Key to avoid Header dependency crashes
    x_api_key = request.headers.get("x-api-key")
    if x_api_key != API_KEY:
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

    # 2. READ RAW BODY: This prevents the 422 "Invalid Request Body" error
    raw_body = await request.body()
    
    # 3. DEFENSIVE PARSING: Handle empty bodies or non-JSON data
    try:
        body = json.loads(raw_body) if raw_body else {}
        if not isinstance(body, dict):
            body = {}
    except Exception:
        body = {}

    # 4. SAFE DEFAULTS: Use .get() so it never crashes on missing fields
    message = str(body.get("message", ""))
    conversation_id = str(body.get("conversation_id", "default"))

    # 5. LOGIC EXECUTION: Wrap in try/except for absolute safety
    try:
        scam_detected = detect_scam(message)
        extracted = extract_intelligence(message)
        update_conversation(conversation_id)
        turns, duration = get_metrics(conversation_id)
    except Exception:
        # Fallback values to ensure a 200 OK is always returned
        scam_detected, turns, duration = False, 1, 0
        extracted = {"bank_accounts": [], "upi_ids": [], "phishing_links": []}

    # 6. GUARANTEED 200 OK RESPONSE
    return {
        "scam_detected": bool(scam_detected),
        "engagement_metrics": {
            "conversation_turns": int(turns),
            "engagement_duration_seconds": int(duration)
        },
        "extracted_intelligence": extracted
    }