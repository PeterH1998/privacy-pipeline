import json
import sys
from pathlib import Path
from parsers.sqlmap_parser import parse_sqlmap_report
from parsers.zap_parser import parse_zap_report

def parse_sarif_report(file_path):
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        tool_name = Path(file_path).stem.capitalize()

        for run in data.get("runs", []):
            driver_name = run.get("tool", {}).get("driver", {}).get("name")
            if driver_name:
                tool_name = driver_name

            for result in run.get("results", []):
                rule_id = result.get("ruleId", "Unknown Vulnerability")
                message = result.get("message", {}).get("text", "No description provided.")
                level = result.get("level", "warning").lower()

                severity_map = {
                    "error": "High",
                    "warning": "Medium",
                    "note": "Low",
                    "none": "Informational"
                }
                severity = severity_map.get(level, "Medium")

                evidence = ""
                locations = result.get("locations", [])
                if locations:
                    phys_loc = locations[0].get("physicalLocation", {})
                    uri = phys_loc.get("artifactLocation", {}).get("uri", "")
                    line = phys_loc.get("region", {}).get("startLine", "")
                    if uri:
                        evidence = f"File: {uri}, Line: {line}"

                findings.append({
                    "source": tool_name,
                    "name": rule_id,
                    "severity": severity,
                    "description": message,
                    "evidence": evidence
                })
    except Exception as e:
        print(f"Error parsing SARIF {file_path}: {e}")

    return findings

def main():
    all_findings = []

    if len(sys.argv) < 2:
        print("Error: Missing required argument (reports directory).")
        print("Usage: python aggregator.py <reports_directory>")
        sys.exit(1)

    reports_dir = Path(sys.argv[1])

    if not reports_dir.exists() or not reports_dir.is_dir():
        print(f"Error: Directory {reports_dir} not found.")
        sys.exit(1)

    print(f"Scanning directory: {reports_dir} for security reports...")

    for file_path in reports_dir.rglob("*"):
        if not file_path.is_file():
            continue

        if file_path.suffix == ".sarif":
            print(f"Processing SARIF report: {file_path.name}")
            sarif_results = parse_sarif_report(file_path)
            if isinstance(sarif_results, list):
                all_findings.extend(sarif_results)

        elif file_path.name == "zap-report.json":
            print(f"Processing ZAP report: {file_path.name}")
            zap_results = parse_zap_report(str(file_path))
            
            if isinstance(zap_results, list):
                all_findings.extend(zap_results)
            else:
                print(f"Error reading ZAP: {zap_results.get('error', 'Unknown error')}")

        elif file_path.name == "sqlmap-output.txt":
            print(f"Processing SQLMap report: {file_path.name}")
            sqlmap_results = parse_sqlmap_report(str(file_path))
            
            if isinstance(sqlmap_results, list):
                all_findings.extend(sqlmap_results)
            else:
                print(f"Error reading SQLMap: {sqlmap_results.get('error', 'Unknown error')}")

    output_file = "aggregated-findings.json"    
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(all_findings, f, indent=2, ensure_ascii=False)
        
    print(f"\nAggregation complete! Exported {len(all_findings)} total findings to {output_file}")

if __name__ == "__main__":
    main()