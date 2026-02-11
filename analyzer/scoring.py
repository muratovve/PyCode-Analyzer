from typing import List, Tuple, Dict
from .models import Finding, ScoreBreakdown

class ScoringEngine:
    def __init__(self):
        pass

    def calculate_score(self, findings: List[Finding]) -> Tuple[int, List[ScoreBreakdown]]:
        total_score = 0
        breakdown = []
        
        # Track counts per technique to prevent score inflation from many identical findings
        # Key: technique name
        technique_counts: Dict[str, int] = {}
        
        for finding in findings:
            if finding.score <= 0:
                continue
            
            technique = finding.technique
            count = technique_counts.get(technique, 0)
            
            # Diminishing returns logic:
            # 1st instance: 100% of score
            # 2nd instance: 50% of score
            # 3rd+ instance: 0% (ignore)
            
            current_increment = 0
            if count == 0:
                current_increment = finding.score
            elif count == 1:
                current_increment = int(finding.score * 0.5)
            else:
                current_increment = 0
            
            if current_increment > 0:
                # Multiplying strictly by 10 to make scores look more substantial 
                # (since we used small ints like 1, 2, 3 in detectors)
                # Or just map small scores to user visible score range (0-100).
                # Current detector max is ~5.
                # Let's scale up: score * 10
                
                final_points = current_increment * 5 
                
                total_score += final_points
                breakdown.append(ScoreBreakdown(
                    rule_name=technique, 
                    score_increment=final_points, 
                    reason=f"{finding.category} - {finding.technique}"
                ))
            
            technique_counts[technique] = count + 1

        # Cap total score at 100
        total_score = min(total_score, 100)
        
        return total_score, breakdown

    def get_level(self, score: int) -> str:
        if score < 20:
            return "LOW"
        elif score < 60:
            return "MEDIUM"
        else:
            return "HIGH"
