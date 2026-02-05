import os
import json
import datetime
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from honeypot_api.app.detector import detect_scam
from honeypot_api.app.extractor import extract_intelligence
from honeypot_api.app.memory import update_conversation, get_metrics
from honeypot_api.app.generator import generate_honeypot_reply

app = FastAPI(title="ShieldGuard Honeypot")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY = os.getenv("API_KEY", "changeme")

@app.post("/honeypot")
@app.get("/debug-key")
async def debug_key(request: Request):
    # This will print the key to your Render "Logs" tab
    received_key = request.headers.get("x-api-key")
    print(f"DEBUG: Received Key -> '{received_key}'")
    print(f"DEBUG: Expected Key -> '{os.getenv('API_KEY')}'")
    return {"message": "Check your Render logs to see the keys compared."}
@app.post("/honeypot/")
async def honeypot(request: Request):
    # 1. Auth check
    if request.headers.get("x-api-key") != API_KEY:
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

    # 2. Defensive Parsing
    try:
        raw_data = await request.body()
        body = json.loads(raw_data.decode("utf-8")) if raw_data else {}
    except Exception:
        body = {}

    message = str(body.get("message") or "")
    conversation_id = str(body.get("conversation_id") or "default_session")

    # 3. Logic: Detect, Extract, and AI Reply
    scam_detected = detect_scam(message)
    extracted = extract_intelligence(message)
    ai_reply = generate_honeypot_reply(message) if scam_detected else "How can I help you?"
    
    # 4. Update Memory
    update_conversation(conversation_id)
    turns, duration = get_metrics(conversation_id)

    # 5. Log Scammer Info
    if scam_detected:
        with open("scammer_intelligence.txt", "a") as f:
            f.write(f"[{datetime.datetime.now()}] ID: {conversation_id} | Msg: {message[:30]} | Info: {extracted}\n")

    return {
        "scam_detected": bool(scam_detected),
        "ai_persona_reply": ai_reply,
        "engagement_metrics": {
            "conversation_turns": int(turns),
            "engagement_duration_seconds": int(duration)
        },
        "extracted_intelligence": extracted
    }

@app.get("/")
async def health():
    return {"status": "online"}