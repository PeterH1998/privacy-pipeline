import json
import re
import sys
from html import unescape
from pathlib import Path


def clean_text(value):
    if value is None:
        return ""

    text = str(value)
    text = unescape(text)
    text = re.sub(r"</p>\s*<p>", "\n", text)
    text = re.sub(r"<br\s*/?>", "\n", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"\n\s*\n+", "\n", text)
    return text.strip()


def extract_severity(riskdesc):
    cleaned = clean_text(riskdesc)

    if not cleaned:
        return "Unknown"

    return cleaned.split("(", 1)[0].strip()


def build_finding(alert, instance, site_name):
    alert_name = clean_text(alert.get("alert") or alert.get("name"))
    riskdesc = clean_text(alert.get("riskdesc"))
    severity = extract_severity(riskdesc)

    url = clean_text(instance.get("uri") or site_name)
    method = clean_text(instance.get("method"))
    parameter = clean_text(instance.get("param"))
    evidence = clean_text(instance.get("evidence"))

    return {
        "source": "ZAP",
        "name": alert_name,
        "severity": severity,
        "url": url,
        "method": method,
        "parameter": parameter,
        "description": clean_text(alert.get("desc")),
        "evidence": evidence,
        "recommendation": clean_text(alert.get("solution")),
        "cwe": clean_text(alert.get("cweid")),
        "metadata": {
            "plugin_id": clean_text(alert.get("pluginid")),
            "alert_ref": clean_text(alert.get("alertRef")),
            "risk_description": riskdesc,
            "confidence": clean_text(alert.get("confidence")),
            "systemic": alert.get("systemic", False),
            "attack": clean_text(instance.get("attack")),
            "other_info": clean_text(instance.get("otherinfo") or alert.get("otherinfo")),
            "source_id": clean_text(alert.get("sourceid"))
        }
    }


def finding_key(finding):
    return (
        finding["source"].lower(),
        finding["name"].lower(),
        finding["severity"].lower(),
        finding["url"].lower(),
        finding["method"].lower(),
        finding["parameter"].lower(),
        finding["evidence"].lower()
    )


def extract_zap_alerts(json_path):
    report_path = Path(json_path)

    with report_path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    findings = []
    seen = set()

    for site in data.get("site", []):
        site_name = clean_text(site.get("@name"))

        for alert in site.get("alerts", []):
            instances = alert.get("instances", [])

            if not instances:
                instances = [{}]

            for instance in instances:
                finding = build_finding(alert, instance, site_name)
                key = finding_key(finding)

                if key not in seen:
                    findings.append(finding)
                    seen.add(key)

    return findings


def main():
    json_path = "tests/reports/zap-report.json"

    if len(sys.argv) > 1:
        json_path = sys.argv[1]

    findings = extract_zap_alerts(json_path)
    print(json.dumps(findings, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()