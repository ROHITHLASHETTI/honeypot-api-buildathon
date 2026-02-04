import os
import json
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# Import your existing logic
from honeypot_api.app.detector import detect_scam
from honeypot_api.app.extractor import extract_intelligence
from honeypot_api.app.memory import update_conversation, get_metrics

app = FastAPI()

# Make sure this matches your Render Environment Variable
API_KEY = os.getenv("API_KEY", "changeme")

@app.post("/honeypot")
async def honeypot(request: Request):
    # 1. Manual Header Validation
    x_api_key = request.headers.get("x-api-key")
    if x_api_key != API_KEY:
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

    # 2. RAW BODY CAPTURE: This is the fix. 
    # It prevents FastAPI from throwing the 'INVALID_REQUEST_BODY' error.
    try:
        raw_data = await request.body()
        # Decode and load JSON manually
        body = json.loads(raw_data.decode("utf-8")) if raw_data else {}
    except Exception:
        # If the tester sends trash or an empty body, we use an empty dict
        body = {}

    # 3. SAFE EXTRACTION: Use .get() so it never crashes if fields are missing
    message = str(body.get("message") or "")
    conversation_id = str(body.get("conversation_id") or "default")

    # 4. EXECUTE LOGIC
    scam_detected = detect_scam(message)
    extracted = extract_intelligence(message)
    update_conversation(conversation_id)
    turns, duration = get_metrics(conversation_id)

    # 5. RETURN CLEAN JSON
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