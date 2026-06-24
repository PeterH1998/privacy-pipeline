import json
import re
import sys
from html import unescape

def clean_html(text):
    if not text:
        return ""
    
    text = unescape(str(text))
    text = re.sub(r"<br\s*/?>|</p>", "\n", text)

    text = re.sub(r"<[^>]+>", "", text)
    
    return text.strip()


def parse_zap_report(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)
    except FileNotFoundError:
        return {"error": f"Could not find file: {file_path}"}

   
    findings = []
    seen_duplicates = set() 


    for site in data.get("site", []):
        site_name = site.get("@name", "UNKNOWN")

        for alert in site.get("alerts", []):
            alert_name = clean_html(alert.get("name", alert.get("alert")))
            
            raw_risk = clean_html(alert.get("riskdesc", ""))
            severity = raw_risk.split("(")[0].strip() if raw_risk else "Unknown"


            instances = alert.get("instances", [{}])

            for instance in instances:
                url = clean_html(instance.get("uri", site_name))
                method = clean_html(instance.get("method", ""))
                parameter = clean_html(instance.get("param", ""))
                evidence = clean_html(instance.get("evidence", ""))
                unique_id = f"{alert_name}_{severity}_{url}_{method}_{parameter}"

                if unique_id not in seen_duplicates:

                    findings.append({
                        "source": "ZAP",
                        "name": alert_name,
                        "severity": severity,
                        "url": url,
                        "method": method,
                        "parameter": parameter,
                        "description": clean_html(alert.get("desc")),
                        "evidence": evidence,
                        "recommendation": clean_html(alert.get("solution")),
                        "cwe": clean_html(alert.get("cweid"))
                    })
                    
                    seen_duplicates.add(unique_id)

    return findings

if __name__ == "__main__":
    file_path = sys.argv[1] if len(sys.argv) > 1 else "zap-report.json"
    
    report_findings = parse_zap_report(file_path)
    print(json.dumps(report_findings, indent=2, ensure_ascii=False))