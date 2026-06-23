import json
import os
import sys
from google import genai

# --- Configuration ---
INPUT_FILE = "master_vulnerability_report.json"  # Updated to match our aggregator output
OUTPUT_FILE = "remediation-report.md"
MODEL_NAME = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")

SYSTEM_PROMPT = """
You are a DevSecOps remediation assistant.

Create a clear Markdown remediation report from security scanner findings.

Rules:
- Use only the findings provided.
- Do not invent vulnerabilities.
- Do not use the word Critical unless a finding has severity Critical.
- Do not add tools that are not mentioned in the project.
- Do not provide offensive exploitation steps.
- Focus on risk, evidence, and safe remediation.
- Prioritize High findings first, then Medium findings.
- Keep the explanation clear for a junior developer.
- Mention the scanner source.
- Output only Markdown.
"""

def severity_score(finding):
    """Helper function to assign a numerical value to severities so we can sort them."""
    scores = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1,
        "Informational": 0
    }
    severity = finding.get("severity", "Informational")
    return scores.get(severity, 0)

def build_prompt(findings):
    """Injects the JSON data into our predefined prompt structure."""
    findings_json = json.dumps(findings, indent=2, ensure_ascii=False)

    return f"""
{SYSTEM_PROMPT}

Create a remediation report for these findings:

{findings_json}

Use this structure:

# Remediation Report

## Executive Summary

## Prioritized Findings

For each finding include:
- Severity
- Source scanner
- Affected location
- Evidence
- Why it matters
- Recommended remediation
- CWE, if available

## Suggested Remediation Order

## Notes for CI/CD Integration
"""

def generate_report_with_gemini(prompt):
    """Handles the actual connection and request to the Gemini API."""
    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        print("Error: Missing GEMINI_API_KEY environment variable.")
        print("Set it with: $env:GEMINI_API_KEY=\"PASTE_YOUR_API_KEY_HERE\"")
        sys.exit(1)

    # Initialize the new genai client
    client = genai.Client(api_key=api_key)

    response = client.models.generate_content(
        model=MODEL_NAME,
        contents=prompt
    )

    return response.text

def main():
    # 1. Read the aggregated findings
    if not os.path.exists(INPUT_FILE):
        print(f"Error: Missing file '{INPUT_FILE}'")
        print("Run the aggregator script first.")
        sys.exit(1)

    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        all_findings = json.load(file)

    # 2. Filter for only Medium, High, and Critical findings
    target_severities = ["Critical", "High", "Medium"]
    key_findings = [f for f in all_findings if f.get("severity") in target_severities]

    # 3. Sort them from highest severity to lowest using our helper function
    key_findings.sort(key=severity_score, reverse=True)

    if not key_findings:
        print("No High or Medium findings found. Skipping report generation.")
        return

    # 4. Prepare the prompt and call Gemini
    print("Connecting to Gemini to generate remediation report...")
    prompt = build_prompt(key_findings)
    report_text = generate_report_with_gemini(prompt)

    # 5. Save the resulting Markdown file
    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        file.write(report_text)

    print(f"Loaded {len(all_findings)} total findings.")
    print(f"Sent {len(key_findings)} key findings to Gemini.")
    print(f"Success: Remediation report saved to '{OUTPUT_FILE}'")

if __name__ == "__main__":
    main()