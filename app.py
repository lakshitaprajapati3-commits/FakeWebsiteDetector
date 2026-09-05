from flask import Flask, render_template, request
from urllib.parse import urlparse
import re

app = Flask(__name__)


def check_website(url):

    score = 0
    reasons = []

    # 1. HTTPS check
    if not url.lower().startswith("https://"):
        score += 2
        reasons.append("Website does not use HTTPS")

    # 2. @ symbol
    if "@" in url:
        score += 3
        reasons.append("URL contains the @ symbol")

    # 3. Suspicious words
    suspicious_words = [
        "free", "offer", "discount", "prize",
        "winner", "login", "verify", "urgent",
        "bonus", "claim", "gift"
    ]

    found_words = []

    for word in suspicious_words:
        if word in url.lower():
            found_words.append(word)

    if found_words:
        score += 2
        reasons.append(
            "Suspicious words found: " + ", ".join(found_words)
        )

    # 4. Very long URL
    if len(url) > 100:
        score += 2
        reasons.append("URL is unusually long")

    # 5. IP address instead of domain
    parsed = urlparse(url)
    hostname = parsed.hostname

    if hostname:

        ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

        if re.match(ip_pattern, hostname):
            score += 3
            reasons.append(
                "Website uses an IP address instead of a domain name"
            )

    # 6. Too many hyphens
    if hostname and hostname.count("-") >= 2:
        score += 2
        reasons.append("Domain contains multiple hyphens")

    # 7. Too many subdomains
    if hostname and hostname.count(".") >= 3:
        score += 2
        reasons.append("URL contains many subdomains")

    # 8. Suspicious URL characters
    if "//" in url[8:]:
        score += 2
        reasons.append("URL contains unusual redirection characters")

    # Maximum score used for percentage
    max_score = 16

    risk_percentage = min(
        round((score / max_score) * 100),
        100
    )

    # Final result
    if score >= 7:
        result = "HIGH RISK - Suspicious Website"
        level = "high"

    elif score >= 3:
        result = "MEDIUM RISK - Be Careful"
        level = "medium"

    else:
        result = "LOW RISK - Looks Relatively Safe"
        level = "low"

    # Additional messages according to risk level
    if level == "low":
        reasons.append("No major suspicious indicators were detected")
        reasons.append("The website has a low risk score")
        reasons.append("No common suspicious URL patterns were found")
        reasons.append("The website appears relatively safe")

    elif level == "medium":
        reasons.append("Some suspicious indicators were detected")
        reasons.append(
            "Please verify the website before entering personal information"
        )
        reasons.append("Be careful before making any payment")
        reasons.append(
            "Check the website details carefully before proceeding"
        )

    elif level == "high":
        reasons.append("Multiple suspicious indicators were detected")
        reasons.append("This website may be unsafe or fraudulent")
        reasons.append(
            "Do not enter personal or banking information"
        )
        reasons.append("Avoid making payments on this website")

    return result, level, score, risk_percentage, reasons


@app.route("/", methods=["GET", "POST"])
def home():

    result = None
    level = None
    score = None
    risk_percentage = None
    reasons = []

    if request.method == "POST":

        url = request.form.get("url", "").strip()

        if url:
            (
                result,
                level,
                score,
                risk_percentage,
                reasons
            ) = check_website(url)

    return render_template(
        "index.html",
        result=result,
        level=level,
        score=score,
        risk_percentage=risk_percentage,
        reasons=reasons
    )


if __name__ == "__main__":
    app.run(debug=True)
