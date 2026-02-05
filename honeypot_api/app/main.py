import os
import json
import datetime
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from honeypot_api.app.detector import detect_scam
from honeypot_api.app.extractor import extract_intelligence
from honeypot_api.app.memory import update_conversation, get_metrics

app = FastAPI(title="ShieldGuard Honeypot")

# Enable CORS for web-based testers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY = os.getenv("API_KEY", "changeme")

@app.post("/honeypot")
@app.post("/honeypot/")
async def honeypot(request: Request):
    # 1. Secure Authentication
    x_api_key = request.headers.get("x-api-key")
    if x_api_key != API_KEY:
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

    # 2. Defensive Parsing (Prevents INVALID_REQUEST_BODY)
    try:
        raw_data = await request.body()
        body = json.loads(raw_data.decode("utf-8")) if raw_data else {}
    except Exception:
        body = {}

    message = str(body.get("message") or "")
    # Ensure ID is consistent for turn tracking
    conversation_id = str(body.get("conversation_id") or "default_session")

    # 3. Logic Execution
    scam_detected = detect_scam(message)
    extracted = extract_intelligence(message)
    
    # 4. Update Memory FIRST so turns increment correctly
    update_conversation(conversation_id)
    turns, duration = get_metrics(conversation_id)

    # 5. WINNING FEATURE: Intelligence Logging
    if scam_detected:
        with open("scammer_intelligence.txt", "a") as f:
            log_entry = (
                f"[{datetime.datetime.now()}] ID: {conversation_id} | "
                f"Scam: {message[:50]}... | "
                f"UPIs: {extracted['upi_ids']} | "
                f"Accounts: {extracted['bank_accounts']}\n"
            )
            f.write(log_entry)

    return {
        "scam_detected": bool(scam_detected),
        "engagement_metrics": {
            "conversation_turns": int(turns),
            "engagement_duration_seconds": int(duration)
        },
        "extracted_intelligence": extracted
    }

@app.get("/")
async def health():
    return {"status": "online"}