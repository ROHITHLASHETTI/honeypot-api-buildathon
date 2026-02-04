import os
import json
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from honeypot_api.app.detector import detect_scam
from honeypot_api.app.extractor import extract_intelligence
from honeypot_api.app.memory import update_conversation, get_metrics

app = FastAPI()

# 1. ALLOW CORS: This lets the web-based tester talk to your API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins for the buildathon
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY = os.getenv("API_KEY", "changeme")

# 2. REDIRECT SLASH: Handles both /honeypot and /honeypot/
@app.post("/honeypot")
@app.post("/honeypot/")
async def honeypot(request: Request):
    # Header check
    x_api_key = request.headers.get("x-api-key")
    if x_api_key != API_KEY:
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

    # RAW BODY CAPTURE (The crash preventer)
    try:
        raw_data = await request.body()
        body = json.loads(raw_data.decode("utf-8")) if raw_data else {}
    except Exception:
        body = {}

    # Safe data extraction
    message = str(body.get("message") or "")
    conversation_id = str(body.get("conversation_id") or "default")

    # Execution
    scam_detected = detect_scam(message)
    extracted = extract_intelligence(message)
    update_conversation(conversation_id)
    turns, duration = get_metrics(conversation_id)

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