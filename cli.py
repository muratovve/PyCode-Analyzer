import argparse
import sys
import os
import json
import logging
from typing import List, Optional
from analyzer.core import Analyzer
from analyzer.models import AnalysisReport
from analyzer.utils import setup_logging

# Setup logging
logger = setup_logging(log_file="logs/analyzer.log")

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import print as rprint
    HAVE_RICH = True
except ImportError:
    HAVE_RICH = False

def print_json(report: AnalysisReport):
    """Outputs report as JSON."""
    data = {
        "file": report.file_path,
        "score": report.total_score,
        "level": report.obfuscation_level,
        "findings": [
            {
                "category": f.category,
                "technique": f.technique,
                "score": f.score,
                "location": str(f.location),
                "snippet": f.snippet
            } for f in report.findings
        ],
        "breakdown": [
            {"rule": b.rule_name, "score": b.score_increment, "reason": b.reason}
            for b in report.score_breakdown
        ],
        "error": report.error
    }
    print(json.dumps(data, indent=2))

def print_json_batch(reports: List[AnalysisReport]):
    """Outputs batch reports as JSON."""
    data = []
    for report in reports:
        data.append({
            "file": report.file_path,
            "score": report.total_score,
            "level": report.obfuscation_level,
            "error": report.error
        })
    print(json.dumps(data, indent=2))

def print_report(report: AnalysisReport):
    """Prints a single file report to console."""
    if report.error:
        logger.error(f"Analysis failed for {report.file_path}: {report.error}")
        print(f"[!] Analysis failed for {report.file_path}: {report.error}")
        return

    if not HAVE_RICH:
        print(f"Analysis Report for: {report.file_path}")
        print(f"Score: {report.total_score} ({report.obfuscation_level})")
        print("\nFindings:")
        for f in report.findings:
            print(f"[{f.category}] {f.technique} (Score: {f.score}) @ {f.location}")
        
        print("\nScore Breakdown:")
        for b in report.score_breakdown:
            print(f"  +{b.score_increment}: {b.rule_name}")
        return

    console = Console()
    
    # Header
    score_color = "green"
    if report.total_score > 20: score_color = "yellow"
    if report.total_score > 60: score_color = "red"
    
    console.print(Panel(
        f"[bold]File:[/bold] {report.file_path}\n[bold]Obf. Level:[/bold] [{score_color}]{report.obfuscation_level}[/{score_color}]", 
        title=f"Results - Score: {report.total_score}", 
        border_style=score_color
    ))

    # Findings Table
    if report.findings:
        table = Table(title="Detected Techniques")
        table.add_column("Category", style="cyan")
        table.add_column("Technique", style="magenta")
        table.add_column("Score", style="yellow")
        table.add_column("Location")
        table.add_column("Snippet/Description", style="dim")

        for f in report.findings:
            table.add_row(
                f.category,
                f.technique,
                str(f.score),
                str(f.location),
                (f.snippet or f.description)[:100]
            )
        console.print(table)

    # Score Breakdown
    if report.score_breakdown:
        console.print("\n[bold]Score Breakdown:[/bold]")
        for b in report.score_breakdown:
            console.print(f"  [red]+{b.score_increment}[/red] {b.rule_name}")

    # Preview
    if report.safe_preview:
        console.print(Panel(report.safe_preview[:500] + ("..." if len(report.safe_preview)>500 else ""), title="Safe Preview (Truncated)", border_style="blue"))

def print_batch_summary(reports: List[AnalysisReport]):
    """Prints a summary table for batch processing."""
    if not HAVE_RICH:
        print("\nBatch Analysis Summary:")
        print(f"{'File':<50} | {'Score':<5} | {'Level':<10}")
        print("-" * 70)
        for r in reports:
            if r.error:
                print(f"{r.file_path:<50} | ERROR | {r.error}")
            else:
                print(f"{r.file_path:<50} | {r.total_score:<5} | {r.obfuscation_level:<10}")
        return

    console = Console()
    table = Table(title="Batch Analysis Summary")
    table.add_column("File", style="cyan")
    table.add_column("Score", justify="right")
    table.add_column("Level", style="bold")
    table.add_column("Status")

    for r in reports:
        if r.error:
            table.add_row(os.path.basename(r.file_path), "-", "-", f"[red]ERROR: {r.error}[/red]")
        else:
            style = "green"
            if r.total_score > 20: style = "yellow"
            if r.total_score > 60: style = "red"
            table.add_row(os.path.basename(r.file_path), str(r.total_score), f"[{style}]{r.obfuscation_level}[/{style}]", "[green]OK[/green]")

    console.print(table)

def process_file(analyzer: Analyzer, path: str) -> AnalysisReport:
    logger.info(f"Analyzing file: {path}")
    if not os.path.exists(path):
        return AnalysisReport(file_path=path, total_score=0, obfuscation_level="ERROR", error="File not found")
    
    # Size check (skip huge files > 1MB to avoid hangs)
    if os.path.getsize(path) > 1024 * 1024:
         logger.warning(f"File too large, skipping: {path}")
         return AnalysisReport(file_path=path, total_score=0, obfuscation_level="SKIPPED", error="File too large (>1MB)")

    return analyzer.analyze_file(path)

def main():
    parser = argparse.ArgumentParser(description="Python Deobfuscator & Obfuscation Detector")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("file", nargs="?", help="Path to python file to analyze")
    group.add_argument("--batch", "-b", help="Directory to scan recursively")
    
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--db", help="Path to SQLite database (optional)")
    parser.add_argument("--save", action="store_true", help="Save results to database")
    
    args = parser.parse_args()
    
    analyzer = Analyzer()
    reports = []
    
    # Batch Processing
    if args.batch:
        if not os.path.isdir(args.batch):
            print(f"Error: {args.batch} is not a directory.")
            sys.exit(1)
            
        logger.info(f"Starting batch analysis on {args.batch}")
        for root, _, files in os.walk(args.batch):
            for file in files:
                if file.endswith(".py"):
                    full_path = os.path.join(root, file)
                    reports.append(process_file(analyzer, full_path))
        
        if args.json:
            print_json_batch(reports)
        else:
            print_batch_summary(reports)

    # Single File
    elif args.file:
        report = process_file(analyzer, args.file)
        if args.json:
            print_json(report)
        else:
            print_report(report)
        
        # for single file mode, if we have reports list populated (we don't for single file logic above unless we refactor), 
        # let's just add it to list for potential DB saving below
        reports.append(report)

    # Database Saving
    if args.save:
        if not args.db:
            args.db = "analysis.db" # Default
        
        try:
            from analyzer.storage import SQLiteStorage
            db = SQLiteStorage(args.db)
            saved_count = 0
            for r in reports: 
                if not r.error:
                    db.save_run(r)
                    saved_count += 1
            
            logger.info(f"Saved {saved_count} runs to {args.db}")
            if not args.json:
                print(f"\n[+] Saved {saved_count} results to database: {args.db}")
        except Exception as e:
            logger.error(f"Failed to save to database: {e}")
            if not args.json:
                print(f"\n[!] Database Error: {e}")

if __name__ == "__main__":
    main()
