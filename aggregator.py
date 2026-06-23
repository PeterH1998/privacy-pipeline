import json
import os

# 1. Import our custom parsers from the 'parsers' folder
from parsers.sqlmap_parser import parse_sqlmap_report
from parsers.zap_parser import parse_zap_report

def main():
    # This master list will hold all vulnerabilities from every tool
    all_findings = []

    # Define where our raw report files live
    sqlmap_file = "tests/reports/sqlmap-output.txt"
    zap_file = "tests/reports/zap-report.json"

    print("Starting security report aggregation...")

    # --- 2. Process SQLMap ---
    print(f"Processing SQLMap report: {sqlmap_file}")
    if os.path.exists(sqlmap_file):
        sqlmap_results = parse_sqlmap_report(sqlmap_file)
        
        if isinstance(sqlmap_results, list):
            all_findings.extend(sqlmap_results)
            print(f"Success: Added {len(sqlmap_results)} SQLMap findings.")
        else:
            print(f"Error reading SQLMap: {sqlmap_results.get('error')}")
    else:
        print("Skipped: SQLMap report not found.")

    # --- 3. Process ZAP ---
    print(f"Processing ZAP report: {zap_file}")
    if os.path.exists(zap_file):
        zap_results = parse_zap_report(zap_file)
        
        if isinstance(zap_results, list):
            all_findings.extend(zap_results)
            print(f"Success: Added {len(zap_results)} ZAP findings.")
        else:
            print(f"Error reading ZAP: {zap_results.get('error')}")
    else:
        print("Skipped: ZAP report not found.")

    # --- 4. Export the Final Master Report ---
    output_file = "master_vulnerability_report.json"
    print(f"Saving combined results to {output_file}...")
    
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(all_findings, f, indent=2, ensure_ascii=False)
    
    print(f"Aggregation complete. Total findings saved: {len(all_findings)}")

if __name__ == "__main__":
    main()