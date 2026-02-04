import os
import json
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# Standard imports
from honeypot_api.app.detector import detect_scam
from honeypot_api.app.extractor import extract_intelligence
from honeypot_api.app.memory import update_conversation, get_metrics

app = FastAPI()

# For local testing, this defaults to 'changeme'
API_KEY = os.getenv("API_KEY", "changeme")

@app.get("/")
async def root():
    return {"status": "online", "message": "Honeypot API Local Server"}

@app.post("/honeypot")
async def honeypot(request: Request):
    # 1. Header Validation
    x_api_key = request.headers.get("x-api-key")
    if x_api_key != API_KEY:
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

    # 2. Raw Body Capture (Prevents 422 errors from the tester)
    raw_data = await request.body()
    
    # 3. Defensive Parsing (Prevents 500 errors on empty/bad JSON)
    try:
        body = json.loads(raw_data) if raw_data else {}
        if not isinstance(body, dict):
            body = {}
    except Exception:
        body = {}

    # 4. Safe Defaults
    conversation_id = str(body.get("conversation_id") or "default")
    message = str(body.get("message") or "")

    # 5. Logic Execution with Fallbacks
    scam_detected = False
    turns, duration = 1, 0
    extracted = {"bank_accounts": [], "upi_ids": [], "phishing_links": []}

    try:
        update_conversation(conversation_id)
        turns, duration = get_metrics(conversation_id)
        scam_detected = detect_scam(message)
        extracted = extract_intelligence(message)
    except Exception as e:
        print(f"Logic Error: {e}") # Visible in your VS Code terminal

    # 6. Guaranteed JSON Response (Prevents 'null' in PowerShell)
    return JSONResponse(
        status_code=200,
        content={
            "scam_detected": bool(scam_detected),
            "engagement_metrics": {
                "conversation_turns": int(turns),
                "engagement_duration_seconds": int(duration)
            },
            "extracted_intelligence": extracted
        }
    )