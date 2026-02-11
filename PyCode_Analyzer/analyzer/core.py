from typing import List, Optional
from .models import AnalysisReport, Finding, ScoreBreakdown
from .detectors.ast_detectors import ASTDetector
from .detectors.static_detectors import StaticDetector
from .detectors.heuristic_detectors import HeuristicDetector
from .scoring import ScoringEngine
from .deobfuscator import SafeDeobfuscator
import os

class Analyzer:
    def __init__(self):
        self.ast_detector = ASTDetector()
        self.static_detector = StaticDetector()
        self.heuristic_detector = HeuristicDetector()
        self.scoring_engine = ScoringEngine()
        self.deobfuscator = SafeDeobfuscator()

    def analyze_file(self, file_path: str) -> AnalysisReport:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
        except Exception as e:
            return AnalysisReport(file_path=file_path, total_score=0, obfuscation_level="ERROR", error=str(e))

        return self.analyze_text(code, file_path)

    def analyze_text(self, code: str, file_path: str = "Input Text") -> AnalysisReport:
        all_findings: List[Finding] = []

        # 1. Run Detectors
        # AST
        all_findings.extend(self.ast_detector.analyze(code))
        
        # Static
        all_findings.extend(self.static_detector.analyze(code))
        
        # Heuristic
        all_findings.extend(self.heuristic_detector.analyze(code))

        # 2. Score
        score, breakdown = self.scoring_engine.calculate_score(all_findings)
        level = self.scoring_engine.get_level(score)

        # 3. Deobfuscate Preview
        preview = self.deobfuscator.try_deobfuscate(code)

        return AnalysisReport(
            file_path=file_path,
            total_score=score,
            obfuscation_level=level,
            findings=all_findings,
            score_breakdown=breakdown,
            safe_preview=preview if preview else None
        )