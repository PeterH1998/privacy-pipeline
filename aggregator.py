import json
import sys
from pathlib import Path
from urllib.parse import urlparse

from parsers.zap_parser import extract_zap_alerts
from parsers.sqlmap_parser import extract_sqlmap_alerts


def get_url_path(url):
    if not url:
        return ""

    parsed_url = urlparse(url)
    return parsed_url.path.lower()


def is_sql_injection(finding):
    name = finding.get("name", "").lower()
    return "sql injection" in name


def same_location(first_finding, second_finding):
    first_path = get_url_path(first_finding.get("url", ""))
    second_path = get_url_path(second_finding.get("url", ""))

    first_parameter = first_finding.get("parameter", "").lower()
    second_parameter = second_finding.get("parameter", "").lower()

    return first_path == second_path and first_parameter == second_parameter


def overlaps_with_sqlmap(zap_finding, sqlmap_findings):
    if not is_sql_injection(zap_finding):
        return False

    for sqlmap_finding in sqlmap_findings:
        if is_sql_injection(sqlmap_finding) and same_location(zap_finding, sqlmap_finding):
            return True

    return False


def aggregate_findings(zap_report_path, sqlmap_report_path):
    zap_findings = extract_zap_alerts(zap_report_path)
    sqlmap_findings = extract_sqlmap_alerts(sqlmap_report_path)

    combined_findings = []

    for sqlmap_finding in sqlmap_findings:
        combined_findings.append(sqlmap_finding)

    for zap_finding in zap_findings:
        if overlaps_with_sqlmap(zap_finding, sqlmap_findings):
            continue

        combined_findings.append(zap_finding)

    return combined_findings


def print_summary(findings):
    for finding in findings:
        severity = finding.get("severity", "Unknown")
        source = finding.get("source", "Unknown")
        name = finding.get("name", "Unknown")
        method = finding.get("method", "")
        url = finding.get("url", "")
        parameter = finding.get("parameter", "")

        if parameter:
            print(f"[{severity}] {source} | {name} | {method} {url} | param: {parameter}")
        else:
            print(f"[{severity}] {source} | {name} | {method} {url}")


def main():
    zap_report_path = Path("tests/reports/zap-report.json")
    sqlmap_report_path = Path("tests/reports/sqlmap-output.txt")

    if len(sys.argv) == 3:
        zap_report_path = Path(sys.argv[1])
        sqlmap_report_path = Path(sys.argv[2])

    findings = aggregate_findings(zap_report_path, sqlmap_report_path)

    print_summary(findings)

    with open("aggregated-findings.json", "w", encoding="utf-8") as file:
        json.dump(findings, file, indent=2, ensure_ascii=False)

    print()
    print(f"Saved {len(findings)} findings to aggregated-findings.json")

if __name__ == "__main__":
    main()