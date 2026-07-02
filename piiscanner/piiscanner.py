from pathlib import Path
import re
import sys
import json

EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_PATTERN = re.compile(r"\+30\d{10}|\b\d{10}\b")
IBAN_PATTERN = re.compile(r"\bGR\d{25}\b")

def mask_email(email):
    local_part, domain = email.split("@", 1)
    masked = local_part[:2] + "***@" + domain
    return masked

def mask_phone(phone):
    digits = phone.strip()
    hidden = "********"
    if phone.startswith("+30"):
        masked = digits[:5]+ hidden
        return masked
    
    masked = digits[:2]+ hidden
    return masked

def mask_iban(iban):
    iban = iban.strip()
    return iban[:4] + "*" * (len(iban) - 4)

def main():
    target_dir = Path(".")
    has_findings = False
    exclude_dir = None

    if "--exclude" in sys.argv:
        exclude_index = sys.argv.index("--exclude")
        if len(sys.argv) > exclude_index + 1:
            exclude_dir = sys.argv[exclude_index + 1]

    if not target_dir.exists():
        print("Couldn't find directory")
        sys.exit(0)

    results = []

    for item in target_dir.rglob("*"):
        if item.is_file():

            if ".git" in item.parts:
                continue

            if exclude_dir and exclude_dir in str(item.as_posix()):
                continue

            with open(item, "r", encoding="utf-8", errors="ignore") as f:
                for line_number, line in enumerate(f, 1):
                    email_matches = EMAIL_PATTERN.findall(line)
                    phone_matches = PHONE_PATTERN.findall(line)
                    iban_matches = IBAN_PATTERN.findall(line)

                    if email_matches:
                        has_findings = True
                        for match in email_matches:
                            masked_match = mask_email(match)
                            results.append({
                                "ruleId": "email",
                                "message": {"text": f"match_preview: {masked_match}"},
                                "locations": [{
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": str(item.as_posix())},
                                        "region": {"startLine": line_number}
                                    }
                                }]
                            })

                    if phone_matches:
                        has_findings = True
                        for match in phone_matches:
                            masked_match = mask_phone(match)
                            results.append({
                                "ruleId": "phone",
                                "message": {"text": f"match_preview: {masked_match}"},
                                "locations": [{
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": str(item.as_posix())},
                                        "region": {"startLine": line_number}
                                    }
                                }]
                            })
                    
                    if iban_matches:
                        has_findings = True
                        for match in iban_matches:
                            masked_match = mask_iban(match)
                            results.append({
                                "ruleId": "iban",
                                "message": {"text": f"match_preview: {masked_match}"},
                                "locations": [{
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": str(item.as_posix())},
                                        "region": {"startLine": line_number}
                                    }
                                }]
                            })


    sarif_output = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Custom PII Scanner"
                    }
                },
                "results": results
            }
        ]
    }

    print(json.dumps(sarif_output, indent=2))

    
    

if __name__ == "__main__":
    main()