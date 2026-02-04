import os
import json
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from honeypot_api.app.detector import detect_scam
from honeypot_api.app.extractor import extract_intelligence
from honeypot_api.app.memory import update_conversation, get_metrics

app = FastAPI()

# Ensure this matches the Environment Variable in Render
API_KEY = os.getenv("API_KEY", "changeme")

@app.post("/honeypot")
async def honeypot(request: Request):
    # 1. Manual Header Check
    x_api_key = request.headers.get("x-api-key")
    if x_api_key != API_KEY:
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

    # 2. Raw Body Extraction
    # We read the body as bytes first to avoid any parsing crashes
    try:
        raw_body = await request.body()
        if not raw_body:
            body = {}
        else:
            # Decode bytes to string and then to JSON
            body = json.loads(raw_body.decode("utf-8"))
    except Exception:
        # If it's not JSON or empty, we treat it as an empty dict
        body = {}

    # 3. Safe Value Extraction
    # The tester might send message: null or conversation_id: 123
    message = str(body.get("message") or "")
    conversation_id = str(body.get("conversation_id") or "default")

    # 4. Process Logic
    try:
        scam_detected = detect_scam(message)
        extracted = extract_intelligence(message)
        update_conversation(conversation_id)
        turns, duration = get_metrics(conversation_id)
    except Exception as e:
        print(f"Logic Error: {e}")
        scam_detected, turns, duration = False, 1, 0
        extracted = {"bank_accounts": [], "upi_ids": [], "phishing_links": []}

    # 5. Forced JSON Response
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

@app.get("/")
async def health():
    return {"status": "online"}