import json
import re
import sys

def parse_sqlmap_report(file_path):
    # 1. Read the file
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            text = file.read()
    except FileNotFoundError:
        return {"error": f"Could not find file: {file_path}"}

    # 2. Extract basic Target & Database info
    # We use simple regex groups (e.g., group(1) is the first parenthesis)
    target_match = re.search(r"\n(GET|POST|PUT|DELETE|PATCH)\s+(https?://\S+)", text)
    method = target_match.group(1) if target_match else "UNKNOWN"
    url = target_match.group(2) if target_match else "UNKNOWN"

    dbms_match = re.search(r"back-end DBMS:\s*(.+)", text)
    dbms = dbms_match.group(1).strip() if dbms_match else "UNKNOWN"

    # 3. Extract the vulnerable parameter
    param_match = re.search(r"Parameter:\s*(\S+)\s*\((\S+)\)", text)
    parameter = param_match.group(1) if param_match else "UNKNOWN"

    # If we didn't find a parameter, there's no vulnerability to report
    if parameter == "UNKNOWN":
        return []

    # 4. Extract the attack techniques
    # We look for blocks containing Type, Title, and Payload
    techniques = []
    technique_pattern = re.findall(r"Type:\s*(.*?)\n\s*Title:\s*(.*?)\n\s*Payload:\s*(.*?)\n", text)
    
    for attack_type, title, payload in technique_pattern:
        techniques.append({
            "type": attack_type.strip(),
            "title": title.strip(),
            "payload": payload.strip()
        })

    # 5. Format the evidence string for the report
    evidence_lines = [f"Backend DBMS: {dbms}"]
    for tech in techniques:
        evidence_lines.append(f"{tech['type']} | {tech['title']} | Payload: {tech['payload']}")
    evidence_string = "\n".join(evidence_lines)

    # 6. Build and return the final JSON structure
    finding = {
        "source": "SQLMap",
        "name": "SQL Injection",
        "severity": "High",
        "url": url,
        "method": method,
        "parameter": parameter,
        "description": "SQLMap confirmed that the target parameter is vulnerable to SQL injection.",
        "evidence": evidence_string,
        "recommendation": "Use parameterized queries, validate input on the server side.",
        "cwe": "89"
    }

    return [finding]

if __name__ == "__main__":
    # Simple way to get the file path from the terminal
    file_path = sys.argv[1] if len(sys.argv) > 1 else "sqlmap-output.txt"
    
    findings = parse_sqlmap_report(file_path)
    print(json.dumps(findings, indent=2))