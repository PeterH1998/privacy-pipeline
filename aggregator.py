import json
import os
import sys
from parsers.sqlmap_parser import parse_sqlmap_report
from parsers.zap_parser import parse_zap_report

def main():
    all_findings = []

    if len(sys.argv) < 3:
        print("Error: Missing required arguments.")
        sys.exit(1)

    zap_file = sys.argv[1]
    sqlmap_file = sys.argv[2]



    if os.path.exists(sqlmap_file):
        sqlmap_results = parse_sqlmap_report(sqlmap_file)
        
        if isinstance(sqlmap_results, list):
            all_findings.extend(sqlmap_results)
        else:
            print(f"Error reading SQLMap: {sqlmap_results.get('error')}")
    else:
        print(f"Skipped: SQLMap report not found at {sqlmap_file}.")


    print(f"Processing ZAP report: {zap_file}")
    if os.path.exists(zap_file):
        zap_results = parse_zap_report(zap_file)
        
        if isinstance(zap_results, list):
            all_findings.extend(zap_results)
        else:
            print(f"Error reading ZAP: {zap_results.get('error')}")
    else:
        print(f"Skipped: ZAP report not found at {zap_file}.")


    output_file = "aggregated-findings.json"    
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(all_findings, f, indent=2, ensure_ascii=False)
    

if __name__ == "__main__":
    main()