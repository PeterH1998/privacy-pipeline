from pathlib import Path
import re
import sys

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
    exclude_dir = None
    has_findings = False

    if "--exclude" in sys.argv:
        exclude_index = sys.argv.index("--exclude")
        if len(sys.argv) > exclude_index + 1:
            exclude_dir = sys.argv[exclude_index + 1]

    if not target_dir.exists():
        print("Couldn't find directory")
        sys.exit(0)

    for item in target_dir.rglob("*"):
        if item.is_file():

            if exclude_dir and exclude_dir in str(item.as_posix()):
                continue

            with open(item, "r", encoding="utf-8") as f:
                for line_number, line in enumerate(f, 1):
                    email_matches = EMAIL_PATTERN.findall(line)
                    phone_matches = PHONE_PATTERN.findall(line)
                    iban_matches = IBAN_PATTERN.findall(line)

                    if email_matches:
                        has_findings = True
                        for match in email_matches:
                            
                            masked_match = mask_email(match)

                            print(f"file: {item}")
                            print(f"line: {line_number}")
                            print("type: email")
                            print(f"match_preview: {masked_match}")
                            print()

                    if phone_matches:
                        has_findings = True
                        for match in phone_matches:
                            masked_match = mask_phone(match)

                            print(f"file: {item}")
                            print(f"line: {line_number}")
                            print("type: phone")
                            print(f"match_preview: {masked_match}")
                            print()
                    
                    if iban_matches:
                        has_findings = True
                        for match in iban_matches:
                            masked_match = mask_iban(match)

                            print(f"file: {item}")
                            print(f"line: {line_number}")
                            print("type: iban")
                            print(f"match_preview: {masked_match}")
                            print()
                
    if has_findings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
