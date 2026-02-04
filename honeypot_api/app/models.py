from pydantic import BaseModel
from typing import List, Dict

class HoneypotRequest(BaseModel):
    conversation_id: str
    message: str

class EngagementMetrics(BaseModel):
    conversation_turns: int
    engagement_duration_seconds: int

class ExtractedIntelligence(BaseModel):
    bank_accounts: List[Dict]
    upi_ids: List[str]
    phishing_links: List[str]

class HoneypotResponse(BaseModel):
    scam_detected: bool
    engagement_metrics: EngagementMetrics
    extracted_intelligence: ExtractedIntelligence
