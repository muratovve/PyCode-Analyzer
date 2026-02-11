from fastapi import FastAPI, File, UploadFile, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Optional, Any
import shutil
import os
import aiofiles

from analyzer.core import Analyzer
from analyzer.models import AnalysisReport
from analyzer.storage import SQLiteStorage

app = FastAPI(title="Python Deobfuscator API", version="1.0")

# Setup Templates
templates = Jinja2Templates(directory="api/templates")

# Models for Request/Response
class AnalyzeRequest(BaseModel):
    code: str
    save: bool = False

class FindingModel(BaseModel):
    category: str
    technique: str
    score: int
    location: str
    snippet: Optional[str] = None

class ReportResponse(BaseModel):
    file_path: Optional[str]
    total_score: int
    level: str
    findings: List[FindingModel]
    error: Optional[str] = None
    run_id: Optional[int] = None
    safe_preview: Optional[str] = None
    score_breakdown: Optional[List[dict]] = None

# Initialize components
analyzer = Analyzer()
storage = SQLiteStorage() # Initialize DB

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/analyze", response_model=ReportResponse)
async def analyze_code(request: AnalyzeRequest):
    """Analyze python code provided in JSON body."""
    report = analyzer.analyze_text(request.code)
    
    run_id = None
    if request.save:
        run_id = storage.save_run(report)

    return _format_response(report, run_id)

@app.post("/analyze/file", response_model=ReportResponse)
async def analyze_file(file: UploadFile = File(...), save: bool = Query(False)):
    """Analyze an uploaded python file."""
    if not file.filename.endswith(".py"):
        raise HTTPException(status_code=400, detail="Only .py files are supported")
    
    # Read file content safely
    content = await file.read()
    try:
        code = content.decode('utf-8')
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File encoding must be UTF-8")

    report = analyzer.analyze_text(code, file_path=file.filename)
    
    run_id = None
    if save:
        run_id = storage.save_run(report)

    return _format_response(report, run_id)

@app.get("/runs")
def list_runs(limit: int = 50):
    """List recent analysis runs from DB."""
    runs = storage.list_runs(limit)
    return runs

@app.get("/runs/{run_id}")
def get_run(run_id: int):
    """Get full details of a specific run."""
    run = storage.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run

def _format_response(report: AnalysisReport, run_id: Optional[int] = None) -> ReportResponse:
    findings = [
        FindingModel(
            category=f.category,
            technique=f.technique,
            score=f.score,
            location=str(f.location),
            snippet=f.snippet
        ) for f in report.findings
    ]
    
    breakdown = [
        {"rule": b.rule_name, "score": b.score_increment, "reason": b.reason}
        for b in report.score_breakdown
    ] if report.score_breakdown else []
    
    return ReportResponse(
        file_path=report.file_path,
        total_score=report.total_score,
        level=report.obfuscation_level,
        findings=findings,
        error=report.error,
        run_id=run_id,
        safe_preview=report.safe_preview,
        score_breakdown=breakdown
    )
