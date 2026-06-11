import re
import os
import json
import datetime
from urllib.parse import urlparse

# ==========================================
# PHISHING EMAIL DETECTION SYSTEM
# ==========================================

HISTORY_FILE = "scan_history.txt"

PHISHING_KEYWORDS = [
    "verify account",
    "update account",
    "login immediately",
    "click here",
    "urgent action",
    "suspended",
    "bank alert",
    "security alert",
    "password expired",
    "confirm identity",
    "limited time",
    "free gift",
    "winner",
    "claim reward",
    "reset password",
    "payment failed",
    "account locked",
    "unauthorized login",
    "act now",
    "important notice"
]

SHORTENER_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly"
]

TRUSTED_DOMAINS = [
    "google.com",
    "microsoft.com",
    "amazon.com",
    "apple.com",
    "github.com",
    "paypal.com"
]

# ==========================================
# SAVE HISTORY
# ==========================================

def save_history(report):

    with open(HISTORY_FILE, "a", encoding="utf-8") as file:
        file.write(json.dumps(report))
        file.write("\n")


# ==========================================
# LOAD HISTORY
# ==========================================

def view_history():

    if not os.path.exists(HISTORY_FILE):
        print("\nNo history available.")
        return

    print("\n========== SCAN HISTORY ==========\n")

    with open(HISTORY_FILE, "r", encoding="utf-8") as file:

        for line in file:
            try:
                data = json.loads(line)

                print("Date:",
                      data["timestamp"])

                print("Risk Score:",
                      data["risk_score"])

                print("Classification:",
                      data["classification"])

                print("-" * 50)

            except:
                pass


# ==========================================
# EXTRACT URLS
# ==========================================

def extract_urls(email_text):

    pattern = r'https?://[^\s]+'

    urls = re.findall(pattern,
                      email_text)

    return urls


# ==========================================
# CHECK PHISHING KEYWORDS
# ==========================================

def keyword_analysis(email_text):

    found = []

    text = email_text.lower()

    for keyword in PHISHING_KEYWORDS:

        if keyword in text:
            found.append(keyword)

    return found


# ==========================================
# URL ANALYSIS
# ==========================================

def url_analysis(urls):

    suspicious = []

    score = 0

    for url in urls:

        parsed = urlparse(url)

        domain = parsed.netloc.lower()

        if domain in SHORTENER_DOMAINS:

            suspicious.append(
                f"URL Shortener Used: {domain}"
            )

            score += 20

        if "@" in url:

            suspicious.append(
                "URL contains @ symbol"
            )

            score += 15

        if len(url) > 80:

            suspicious.append(
                "Very long URL"
            )

            score += 10

        if domain.replace("www.", "") \
                not in TRUSTED_DOMAINS:

            suspicious.append(
                f"Unknown Domain: {domain}"
            )

            score += 10

    return suspicious, score


# ==========================================
# EMAIL ANALYSIS
# ==========================================

def analyze_email(email_text):

    score = 0

    findings = []

    keywords = keyword_analysis(
        email_text
    )

    if keywords:

        findings.append(
            f"Phishing Keywords Found: "
            f"{', '.join(keywords)}"
        )

        score += len(keywords) * 5

    urls = extract_urls(
        email_text
    )

    if urls:

        findings.append(
            f"{len(urls)} URL(s) Found"
        )

    url_findings, url_score = \
        url_analysis(urls)

    findings.extend(url_findings)

    score += url_score

    upper_count = sum(
        1 for c in email_text
        if c.isupper()
    )

    if upper_count > 40:

        findings.append(
            "Excessive Capital Letters"
        )

        score += 10

    exclamations = \
        email_text.count("!")

    if exclamations > 5:

        findings.append(
            "Too Many Exclamation Marks"
        )

        score += 10

    if score < 20:
        classification = "Safe"

    elif score < 50:
        classification = "Suspicious"

    else:
        classification = "Likely Phishing"

    report = {

        "timestamp":
        str(datetime.datetime.now()),

        "risk_score": score,

        "classification":
        classification,

        "findings": findings
    }

    return report


# ==========================================
# DISPLAY REPORT
# ==========================================

def display_report(report):

    print("\n")
    print("=" * 60)
    print("PHISHING DETECTION REPORT")
    print("=" * 60)

    print(
        f"Risk Score: "
        f"{report['risk_score']}/100"
    )

    print(
        f"Classification: "
        f"{report['classification']}"
    )

    print("\nFindings:")

    if report["findings"]:

        for item in report["findings"]:
            print("•", item)

    else:
        print("No suspicious indicators")

    print("=" * 60)


# ==========================================
# SECURITY ADVICE
# ==========================================

def recommendations(score):

    print("\nRecommendations:")

    if score < 20:

        print(
            "- Email appears safe."
        )

    elif score < 50:

        print(
            "- Verify sender identity."
        )

        print(
            "- Do not click unknown links."
        )

    else:

        print(
            "- Possible phishing attempt."
        )

        print(
            "- Do not open attachments."
        )

        print(
            "- Report to security team."
        )

        print(
            "- Delete the email."
        )


# ==========================================
# EMAIL INPUT
# ==========================================

def scan_email():

    print(
        "\nPaste Email Content."
    )

    print(
        "Type END on a new line "
        "when finished.\n"
    )

    lines = []

    while True:

        line = input()

        if line.strip() == "END":
            break

        lines.append(line)

    email_text = "\n".join(lines)

    report = analyze_email(
        email_text
    )

    display_report(report)

    recommendations(
        report["risk_score"]
    )

    save_history(report)


# ==========================================
# SAMPLE TEST
# ==========================================

def sample_email():

    email = """
URGENT ACTION REQUIRED!

Your account has been suspended.

Click here immediately:

https://bit.ly/freegift123

Verify account now.

Limited time offer!!!

    """

    report = analyze_email(
        email
    )

    display_report(report)


# ==========================================
# MENU
# ==========================================

def menu():

    while True:

        print("\n")
        print("=" * 50)
        print("PHISHING EMAIL DETECTOR")
        print("=" * 50)

        print("1. Scan Email")
        print("2. View History")
        print("3. Run Sample Test")
        print("4. Exit")

        choice = input(
            "\nChoose Option: "
        )

        if choice == "1":

            scan_email()

        elif choice == "2":

            view_history()

        elif choice == "3":

            sample_email()

        elif choice == "4":

            print(
                "\nExiting Program..."
            )

            break

        else:

            print(
                "Invalid Choice"
            )


# ==========================================
# MAIN
# ==========================================

if __name__ == "__main__":

    print("\n")
    print("=" * 60)
    print("CYBER SECURITY PROJECT")
    print("PHISHING EMAIL DETECTION SYSTEM")
    print("=" * 60)

    menu()