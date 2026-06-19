import json
import re
import sys
from pathlib import Path


def clean_text(value):
    if value is None:
        return ""

    text = str(value)
    text = text.replace("\r\n", "\n")
    text = re.sub(r"\n\s*\n+", "\n", text)
    return text.strip()



def extract_target(text):
    match = re.search(r"\n(GET|POST|PUT|DELETE|PATCH)\s+(https?://\S+)", text)

    if not match:
        return "", ""

    method = match.group(1).strip()
    url = match.group(2).strip()

    return method, url


def extract_dbms(text):
    match = re.search(r"back-end DBMS:\s*(.+)", text)

    if not match:
        return ""

    return match.group(1).strip()


def extract_parameter_block(text):
    match = re.search(
        r"Parameter:\s*(?P<parameter>\S+)\s*\((?P<method>\S+)\)(?P<body>.*?)(?:\n---|\Z)",
        text,
        re.DOTALL
    )

    if not match:
        return "", "", ""

    parameter = match.group("parameter").strip()
    method = match.group("method").strip()
    body = match.group("body").strip()

    return parameter, method, body


def extract_techniques(block):
    techniques = []

    pattern = re.compile(
        r"Type:\s*(?P<type>.*?)\n\s*Title:\s*(?P<title>.*?)\n\s*Payload:\s*(?P<payload>.*?)(?=\n\s*Type:|\Z)",
        re.DOTALL
    )

    for match in pattern.finditer(block):
        technique = {
            "type": clean_text(match.group("type")),
            "title": clean_text(match.group("title")),
            "payload": clean_text(match.group("payload"))
        }

        techniques.append(technique)

    return techniques


def build_evidence(techniques, dbms):
    evidence_parts = []

    if dbms:
        evidence_parts.append(f"Backend DBMS: {dbms}")

    for technique in techniques:
        evidence_parts.append(
            f"{technique['type']} | {technique['title']} | Payload: {technique['payload']}"
        )

    return "\n".join(evidence_parts)


def build_finding(url, method, parameter, dbms, techniques):
    return {
        "source": "SQLMap",
        "name": "SQL Injection",
        "severity": "High",
        "url": url,
        "method": method,
        "parameter": parameter,
        "description": "SQLMap confirmed that the target parameter is vulnerable to SQL injection.",
        "evidence": build_evidence(techniques, dbms),
        "recommendation": "Use parameterized queries, validate input on the server side, and avoid building SQL queries through string concatenation.",
        "cwe": "89",
        "metadata": {
            "dbms": dbms,
            "techniques": techniques
        }
    }


def extract_sqlmap_alerts(txt_path):
    report_path = Path(txt_path)

    with report_path.open("r", encoding="utf-8") as file:
        text = file.read()

    target_method, target_url = extract_target(text)
    parameter, parameter_method, block = extract_parameter_block(text)
    dbms = extract_dbms(text)
    techniques = extract_techniques(block)

    if not parameter or not techniques:
        return []

    method = parameter_method or target_method

    finding = build_finding(
        url=target_url,
        method=method,
        parameter=parameter,
        dbms=dbms,
        techniques=techniques
    )

    return [finding]


def main():
    txt_path = "tests/reports/sqlmap-output.txt"

    if len(sys.argv) > 1:
        txt_path = sys.argv[1]

    findings = extract_sqlmap_alerts(txt_path)
    print(json.dumps(findings, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()