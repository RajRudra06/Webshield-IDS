from pydantic import BaseModel
from typing import List, Optional

class URLFeatures(BaseModel):
    features: List[float]

class URLRequest(BaseModel):
    url: str

class PredictionResponse(BaseModel):
    threat_detected: bool
    confidence: float
    model_used: str
    reasons: Optional[List[str]] = []

class Feedback(BaseModel):
    url: str
    user_label: str  # "benign" or "malicious"
    model_pred: Optional[bool] = None
