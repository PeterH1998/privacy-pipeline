import json
import re
import sys
from html import unescape

def clean_html(text):
    """A simple helper to remove HTML tags and decode HTML entities."""
    if not text:
        return ""
    
    # 1. Convert HTML entities (like &lt;) back to normal characters
    text = unescape(str(text))
    # 2. Swap break/paragraph tags for actual newlines so it reads nicely
    text = re.sub(r"<br\s*/?>|</p>", "\n", text)
    # 3. Strip all remaining HTML tags (anything inside < >)
    text = re.sub(r"<[^>]+>", "", text)
    
    return text.strip()

def parse_zap_report(file_path):
    # 1. Read the JSON file
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)
    except FileNotFoundError:
        return {"error": f"Could not find file: {file_path}"}

    findings = []
    seen_duplicates = set() # We'll store unique IDs here to avoid duplicates

    # 2. Loop through the sites scanned by ZAP
    for site in data.get("site", []):
        site_name = site.get("@name", "UNKNOWN")

        # 3. Loop through the security alerts found on this site
        for alert in site.get("alerts", []):
            alert_name = clean_html(alert.get("name", alert.get("alert")))
            
            # ZAP formats risk as "High (Warning)". We just want the "High" part.
            raw_risk = clean_html(alert.get("riskdesc", ""))
            severity = raw_risk.split("(")[0].strip() if raw_risk else "Unknown"

            # 4. Loop through the specific instances (URLs/Parameters) where it was found
            # If there are no instances, we provide one empty dictionary to loop once
            instances = alert.get("instances", [{}])

            for instance in instances:
                url = clean_html(instance.get("uri", site_name))
                method = clean_html(instance.get("method", ""))
                parameter = clean_html(instance.get("param", ""))
                evidence = clean_html(instance.get("evidence", ""))

                # Create a simple unique ID string to check if we've seen this exact flaw already
                unique_id = f"{alert_name}_{severity}_{url}_{method}_{parameter}"

                if unique_id not in seen_duplicates:
                    # 5. Build the final finding
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
    # Get the file path from the terminal, or use a default
    file_path = sys.argv[1] if len(sys.argv) > 1 else "zap-report.json"
    
    report_findings = parse_zap_report(file_path)
    print(json.dumps(report_findings, indent=2, ensure_ascii=False))