from dataclasses import dataclass, field
from typing import List, Optional, Any

@dataclass
class Finding:
    category: str  # e.g., "AST", "String", "Heuristic"
    technique: str  # e.g., "Exec Usage", "Base64 Blob"
    confidence: str  # "LOW", "MEDIUM", "HIGH"
    location: str  # Line number or description of where it was found
    snippet: Optional[str] = None
    score: int = 0
    description: str = ""

@dataclass
class ScoreBreakdown:
    rule_name: str
    score_increment: int
    reason: str

@dataclass
class AnalysisReport:
    file_path: str
    total_score: int
    obfuscation_level: str  # "LOW", "MEDIUM", "HIGH"
    findings: List[Finding] = field(default_factory=list)
    score_breakdown: List[ScoreBreakdown] = field(default_factory=list)
    safe_preview: Optional[str] = None
    error: Optional[str] = None
