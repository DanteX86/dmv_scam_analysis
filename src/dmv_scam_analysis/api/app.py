"""FastAPI application for DMV scam analysis."""
from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing import List, Dict, Optional
from datetime import datetime
from pydantic import BaseModel, Field

from ..core.classifier import MLThreatClassifier as ThreatClassifier
from ..analysis.behavioral import BehavioralAnalyzer
from ..utils.rate_limiter import RateLimiter

app = FastAPI(
    title="DMV Scam Analysis API",
    description="API for analyzing and detecting DMV-related scams",
    version="1.0.0"
)

# Security
security = HTTPBearer()
rate_limiter = RateLimiter(max_requests=100, time_window=60)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize components
classifier = ThreatClassifier()
analyzer = BehavioralAnalyzer()

# Models
class Message(BaseModel):
    """Model for message data."""
    text: str = Field(..., description="The message text to analyze")
    source: str = Field(..., description="Source of the message (email, sms, web, etc.)")
    timestamp: datetime = Field(default_factory=datetime.now)
    metadata: Optional[Dict] = Field(default=None, description="Additional metadata")

class AnalysisResponse(BaseModel):
    """Model for analysis response."""
    threat_score: float
    classification: str
    indicators: List[str]
    confidence: float
    analysis_id: str

# Dependencies
def get_token(credentials: HTTPAuthorizationCredentials = Security(security)) -> str:
    """Validate and return the authentication token."""
    return credentials.credentials

async def check_rate_limit(token: str = Depends(get_token)):
    """Check if the request is within rate limits."""
    if not await rate_limiter.check_rate_limit(token):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

# Routes
@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_message(
    message: Message,
    token: str = Depends(get_token),
    _: None = Depends(check_rate_limit)
) -> AnalysisResponse:
    """Analyze a potential scam message."""
    try:
        # Get threat score
        threat_score = classifier.predict([message.text])[0]
        
        # Get behavioral analysis
        behavior_analysis = analyzer.analyze([message.dict()])
        
        return AnalysisResponse(
            threat_score=float(threat_score),
            classification="high_risk" if threat_score > 0.7 else "medium_risk" if threat_score > 0.3 else "low_risk",
            indicators=behavior_analysis["indicators"],
            confidence=behavior_analysis["confidence"],
            analysis_id=behavior_analysis["analysis_id"]
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/stats")
async def get_statistics(
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    token: str = Depends(get_token),
    _: None = Depends(check_rate_limit)
) -> Dict:
    """Get analysis statistics for a date range."""
    try:
        stats = analyzer.get_statistics(start_date, end_date)
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check() -> Dict:
    """Check API health status."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }

# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Handle HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "timestamp": datetime.now().isoformat()
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Handle general exceptions."""
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc),
            "timestamp": datetime.now().isoformat()
        }
    )
