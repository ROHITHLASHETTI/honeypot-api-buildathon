import os
import json
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# Logic imports (ensure these files are in your honeypot_api/app/ folder)
from honeypot_api.app.detector import detect_scam
from honeypot_api.app.extractor import extract_intelligence
from honeypot_api.app.memory import update_conversation, get_metrics

app = FastAPI()

# Enable CORS so the web-based tester can communicate with Render
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
    # 1. Validate Header
    x_api_key = request.headers.get("x-api-key")
    if x_api_key != API_KEY:
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

    # 2. Extract Body Defensively
    try:
        raw_data = await request.body()
        body = json.loads(raw_data.decode("utf-8")) if raw_data else {}
    except Exception:
        body = {}

    # 3. Safe Defaults for Logic
    message = str(body.get("message") or "")
    conversation_id = str(body.get("conversation_id") or "default")

    # 4. Run Logic
    scam_detected = detect_scam(message)
    extracted = extract_intelligence(message)
    update_conversation(conversation_id)
    turns, duration = get_metrics(conversation_id)

    # 5. Exact Response Structure
    return {
        "scam_detected": bool(scam_detected),
        "engagement_metrics": {
            "conversation_turns": int(turns),
            "engagement_duration_seconds": int(duration)
        },
        "extracted_intelligence": extracted
    }