import sqlite3
import argparse
import os
import sys
from collections import Counter
import matplotlib.pyplot as plt

def generate_report(db_path, out_dir):
    if not os.path.exists(db_path):
        print(f"Error: Database not found at {db_path}")
        return

    os.makedirs(out_dir, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 1. Fetch Stats
    cursor.execute("SELECT total_score, level FROM runs")
    runs = cursor.fetchall()
    
    if not runs:
        print("No runs found in database.")
        return

    scores = [r["total_score"] for r in runs]
    levels = [r["level"] for r in runs]
    
    cursor.execute("SELECT technique FROM findings")
    findings = cursor.fetchall()
    techniques = [f["technique"] for f in findings]

    # 2. Text Summary
    print(f"--- Analysis Report ---")
    print(f"Total Runs: {len(runs)}")
    print(f"Avg Score: {sum(scores)/len(scores):.2f}")
    print(f"Max Score: {max(scores)}")
    print(f"High Risk Runs: {levels.count('HIGH')}")
    
    top_techniques = Counter(techniques).most_common(5)
    print("\nTop Techniques:")
    for t, c in top_techniques:
        print(f"  {t}: {c}")

    # 3. Charts
    # Histogram of Scores
    plt.figure(figsize=(10, 6))
    plt.hist(scores, bins=20, color='skyblue', edgecolor='black')
    plt.title("Distribution of Threat Scores")
    plt.xlabel("Score")
    plt.ylabel("Count")
    plt.savefig(os.path.join(out_dir, "score_dist_hist.png"))
    plt.close()
    
    # Technique Bar Chart
    if top_techniques:
        plt.figure(figsize=(10, 6))
        techs, counts = zip(*top_techniques)
        plt.barh(techs, counts, color='salmon')
        plt.title("Top Detection Techniques")
        plt.xlabel("Count")
        plt.tight_layout()
        plt.savefig(os.path.join(out_dir, "top_techniques_bar.png"))
        plt.close()

    print(f"\nCharts saved to {out_dir}/")
    conn.close()

def main():
    parser = argparse.ArgumentParser(description="Generate charts from analysis database")
    parser.add_argument("--db", default="analysis.db", help="Path to sqlite db")
    parser.add_argument("--out", default="reports", help="Output directory for charts")
    args = parser.parse_args()
    
    try:
        generate_report(args.db, args.out)
    except Exception as e:
        print(f"Error generating report: {e}")

if __name__ == "__main__":
    main()
