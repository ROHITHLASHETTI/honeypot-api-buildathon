import os
import json
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from honeypot_api.app.detector import detect_scam
from honeypot_api.app.extractor import extract_intelligence
from honeypot_api.app.memory import update_conversation, get_metrics
from honeypot_api.app.models import HoneypotRequest, HoneypotResponse

app = FastAPI(title="Buildathon Honeypot API")

API_KEY = os.getenv("API_KEY", "changeme")

@app.get("/")
async def root():
    return {"status": "online", "message": "Honeypot API is live."}

@app.post("/honeypot", response_model=HoneypotResponse)
async def honeypot(request: Request):
    # 1. Header Validation
    x_api_key = request.headers.get("x-api-key")
    if x_api_key != API_KEY:
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

    # 2. Defensive JSON Parsing
    raw_data = await request.body()
    try:
        data_json = json.loads(raw_data) if raw_data else {}
        payload = HoneypotRequest(**data_json)
    except Exception:
        payload = HoneypotRequest() # Use defaults if JSON is broken

    # 3. Logic Execution
    scam_detected = detect_scam(payload.message)
    extracted = extract_intelligence(payload.message)
    update_conversation(payload.conversation_id)
    turns, duration = get_metrics(payload.conversation_id)

    # 4. Return valid JSON
    return {
        "scam_detected": bool(scam_detected),
        "engagement_metrics": {
            "conversation_turns": int(turns),
            "engagement_duration_seconds": int(duration)
        },
        "extracted_intelligence": extracted
    }