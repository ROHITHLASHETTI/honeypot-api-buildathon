import os
import json
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# Ensure these modules exist in your /app folder
from honeypot_api.app.detector import detect_scam
from honeypot_api.app.extractor import extract_intelligence
from honeypot_api.app.memory import update_conversation, get_metrics

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY = os.getenv("API_KEY", "changeme")

@app.get("/")
async def health():
    return {"status": "online"}

@app.post("/honeypot")
async def honeypot(request: Request):
    # 1. AUTH CHECK (Returns 401 if wrong, passes if correct)
    if request.headers.get("x-api-key") != API_KEY:
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

    # 2. DEFENSIVE PARSING
    try:
        raw_data = await request.body()
        body = json.loads(raw_data.decode("utf-8")) if raw_data else {}
    except Exception:
        body = {}

    message = str(body.get("message") or "")
    conversation_id = str(body.get("conversation_id") or "default")

    # 3. CORE LOGIC (This is what wins the hackathon)
    scam_detected = detect_scam(message)
    extracted = extract_intelligence(message)
    
    # 4. SESSION TRACKING
    update_conversation(conversation_id)
    turns, duration = get_metrics(conversation_id)

    # 5. THE CORRECT JSON RESPONSE
    # No more "Check your Render logs" text here!
    return {
        "scam_detected": bool(scam_detected),
        "engagement_metrics": {
            "conversation_turns": int(turns),
            "engagement_duration_seconds": int(duration)
        },
        "extracted_intelligence": extracted
    }