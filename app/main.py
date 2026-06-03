from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.analyzer import analyze_url, load_known_brand_domains


app = FastAPI(
    title="PhishGuard",
    description="Analyse passive et limitee d'URL pour estimer un risque de phishing.",
    version="1.0.0",
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")


class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="URL a analyser")
    demo_mode: bool = Field(False, description="Desactive les controles reseau pour les demos")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse("app/static/index.html")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/brands")
async def brands() -> dict:
    known_brands = load_known_brand_domains()
    return {
        "count": len(known_brands),
        "brands": known_brands,
    }


@app.post("/api/analyze")
async def analyze(request: AnalyzeRequest) -> dict:
    try:
        return await analyze_url(request.url, demo_mode=request.demo_mode)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
