import json
import os
import sys
from pathlib import Path

from google import genai

MODEL_NAME = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")
INPUT_FILE = Path("aggregated-findings.json")
OUTPUT_FILE = Path("agent-report.md")


def load_findings(file_path):
    if not file_path.exists():
        print(f"Missing file: {file_path}")
        sys.exit(1)

    with file_path.open("r", encoding="utf-8") as file:
        return json.load(file)


def severity_score(finding):
    scores = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1,
        "Informational": 0
    }
    severity = finding.get("severity", "Informational")
    return scores.get(severity, 0)


def select_key_findings(findings):
    selected = []
    for finding in findings:
        severity = finding.get("severity", "")
        if severity in ["Critical", "High", "Medium"]:
            selected.append(finding)

    selected.sort(key=severity_score, reverse=True)
    return selected


def simplify_finding(finding):
    return {
        "source": finding.get("source", ""),
        "name": finding.get("name", ""),
        "severity": finding.get("severity", ""),
        "url": finding.get("url", ""),
        "method": finding.get("method", ""),
        "parameter": finding.get("parameter", ""),
        "description": finding.get("description", ""),
        "evidence": finding.get("evidence", ""),
        "recommendation": finding.get("recommendation", ""),
        "cwe": finding.get("cwe", ""),
        "metadata": finding.get("metadata", {})
    }


def build_prompt(findings):
    
    simplified_findings = []

    for finding in findings:
        simplified_findings.append(simplify_finding(finding))

    findings_json = json.dumps(simplified_findings, indent=2, ensure_ascii=False)

    return f"""
Your role is a DevOps fix guidance assistant.

Your job is to create a clear Markdown fix report from security scanner findings.

Rules:
    Use only the findings provided.
    Do not invent vulnerabilities.
    Do not use the word Critical unless a finding has severity Critical.
    Do not add tools that are not mentioned in the project.
    Focus on risk, evidence, and safe fix guidance.
    Prioritize High findings first, then Medium findings.
    Keep the explanation clear and simple.
    Mention the scanner source.
    Output only Markdown.

    Categorization Rules:
    - You must separate findings into two categories: "Dynamic Security Findings" and "Static Security Findings".
    - Dynamic sources include: "ZAP", "SQLMap".
    - Static sources include: "Trivy", "Gitleaks", "CodeQL", "Custom PII Scanner".
    - Present Dynamic Security Findings first.
Create a fix report for these findings:

{findings_json}

Use this structure:

1. Fix Report
2. Executive Summary
3. Prioritized Dynamic Findings
4. Prioritized Static Findings

For each finding include:
- Severity
- Source scanner
- Affected location
- Evidence
- Why it matters
- Recommended fixes

5. Suggested fix Order
"""


def call_gemini(prompt):
    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        print("Missing GEMINI_API_KEY environment variable.")
        sys.exit(1)

    client = genai.Client(api_key=api_key)

    response = client.models.generate_content(
        model=MODEL_NAME,
        contents=prompt
    )

    # Extract token usage metadata from the response
    usage = response.usage_metadata
    prompt_tokens = usage.prompt_token_count
    candidate_tokens = usage.candidates_token_count
    total_tokens = usage.total_token_count

    # Format the token usage display
    token_footer = (
        f"\n\n---\n"
        f"### 📊 AI Token Usage Metrics\n"
        f"- **Prompt Tokens:** `{prompt_tokens}`\n"
        f"- **Output Tokens:** `{candidate_tokens}`\n"
        f"- **Total Tokens:** `{total_tokens}`\n"
    )

    # Append the token tracking to the generated report text
    return response.text + token_footer


def save_report(report_text, output_path):
    output_path.write_text(report_text, encoding="utf-8")


def main():
    findings = load_findings(INPUT_FILE)
    key_findings = select_key_findings(findings)

    if not key_findings:
        print("No fix report was generated. (No key findings found)")
        return

    prompt = build_prompt(key_findings)
    report_text = call_gemini(prompt)

    save_report(report_text, OUTPUT_FILE)
    print(f"Saved report to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()