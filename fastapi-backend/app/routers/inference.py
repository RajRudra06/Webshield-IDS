from fastapi import APIRouter, HTTPException
from ..models import URLFeatures, PredictionResponse
from ..utils.model_loader import predict_ensemble

router = APIRouter()

@router.post("/", response_model=PredictionResponse)
def predict_url(data: URLFeatures):
    try:
        is_threat, conf, model_name = predict_ensemble(data.features)
        return PredictionResponse(
            threat_detected=is_threat,
            confidence=conf,
            model_used=model_name
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
