import re
from dataclasses import dataclass, field
from typing import List


@dataclass
class Finding:
    text: str
    score: int
    severity: str


@dataclass
class AnalysisResult:
    score: int
    findings: List[Finding]
    verdict: str
    color: str
    stamp: str
    description: str


SAMPLES = {
    "url": [
        "http://paypa1-secure-login.verify-account-update.tk/signin.php",
        "https://www.wikipedia.org/wiki/Phishing",
    ],
    "email": [
        """From: security@paypa1-alerts.com
Subject: URGENT: Your account will be suspended in 24 hours!!!

Dear Valued Customer,

We have detected unusual activity on your account. Your access will be suspended within 24 hours unless you verify your identity immediately.

Please click here to confirm your password and credit card details: http://paypa1-secure-login.verify-account-update.tk/signin.php

Failure to act now will result in permanent account closure.

Regards,
Security Team""",
        """From: newsletter@wikipedia.org
Subject: This week's featured articles

Hi there,

Here is a roundup of this week's most-read articles on Wikipedia, curated by our volunteer editors. As always, thank you for supporting free knowledge.

Best,
The Wikimedia Team""",
    ],
}


def severity_rank(severity: str) -> int:
    return {"high": 3, "med": 2, "low": 1}.get(severity, 0)


def analyze_url(raw_url: str) -> AnalysisResult:
    findings: List[Finding] = []
    score = 0
    url = raw_url.strip()
    if not url:
        return build_result(0, [], "LIKELY SAFE", "#3ECF8E", "CLEARED", "No suspicious input was provided.")

    has_protocol = re.match(r"^https?://", url, re.I)
    working_url = url if has_protocol else f"http://{url}"
    hostname = ""
    try:
        hostname = re.sub(r"^www\.", "", re.split(r"//", working_url)[1].split("/")[0].lower())
    except IndexError:
        hostname = url.split("/")[0].lower()

    full = url.lower()

    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", hostname):
        findings.append(Finding("Domain is a raw IP address instead of a registered name", 30, "high"))
    if "@" in url:
        findings.append(Finding('URL contains an "@" symbol, often used to disguise the real destination', 25, "high"))

    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"]
    if any(s in hostname for s in shorteners):
        findings.append(Finding("Uses a URL shortening service, which hides the true destination", 15, "med"))
    if not full.startswith("https://"):
        findings.append(Finding("Connection is not encrypted with HTTPS", 10, "med"))

    bad_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work", ".click", ".loan", ".men"]
    for suffix in bad_tlds:
        if hostname.endswith(suffix):
            findings.append(Finding(f"Uses a top-level domain frequently associated with abuse ({suffix})", 15, "med"))
            break

    dot_count = hostname.count(".")
    if dot_count >= 4:
        findings.append(Finding("Unusually high number of subdomains, a common cloaking technique", 10, "low"))

    brands = ["paypal", "apple", "microsoft", "amazon", "google", "facebook", "netflix", "bank", "instagram", "chase", "wellsfargo"]
    mentioned_brand = next((brand for brand in brands if brand in hostname), None)
    if mentioned_brand:
        official_map = {
            "paypal": "paypal.com",
            "apple": "apple.com",
            "microsoft": "microsoft.com",
            "amazon": "amazon.com",
            "google": "google.com",
            "facebook": "facebook.com",
            "netflix": "netflix.com",
            "instagram": "instagram.com",
            "chase": "chase.com",
            "wellsfargo": "wellsfargo.com",
        }
        official = official_map.get(mentioned_brand)
        if official and hostname != official and not hostname.endswith("." + official):
            findings.append(Finding(f'References brand "{mentioned_brand}" but domain does not match the official site', 25, "high"))

    if re.search(r"paypa1|micr0soft|g00gle|arnaz0n|faceb00k|0utlook|rn(?=icrosoft)", hostname, re.I):
        findings.append(Finding("Domain uses look-alike character substitution to mimic a trusted brand", 20, "high"))
    if "xn--" in hostname:
        findings.append(Finding("Domain uses punycode encoding, a known technique for homograph attacks", 20, "high"))

    keywords = ["verify", "secure", "account", "update", "confirm", "login", "signin", "banking", "suspend", "unlock", "billing"]
    kw_hits = [k for k in keywords if k in full]
    if len(kw_hits) >= 2:
        findings.append(Finding(f"Multiple urgency/credential-related keywords in the URL ({', '.join(kw_hits[:3])})", 15, "med"))
    elif len(kw_hits) == 1:
        findings.append(Finding(f'Contains credential-related keyword "{kw_hits[0]}"', 6, "low"))
    if len(url) > 90:
        findings.append(Finding("Unusually long URL, often used to obscure the true domain", 8, "low"))
    if len(re.findall(r"-", hostname)) >= 3:
        findings.append(Finding("Domain contains an unusually high number of hyphens", 10, "low"))

    score = min(100, sum(f.score for f in findings))
    findings.sort(key=lambda item: severity_rank(item.severity), reverse=True)
    return build_result(score, findings)


def analyze_email(text: str) -> AnalysisResult:
    findings: List[Finding] = []
    if not text.strip():
        return build_result(0, [], "LIKELY SAFE", "#3ECF8E", "CLEARED", "No suspicious input was provided.")

    lower = text.lower()

    if re.search(r"dear (customer|valued customer|user|member|sir/madam|account holder)", lower):
        findings.append(Finding("Uses a generic greeting instead of the recipient's name", 10, "low"))

    urgency_phrases = ["immediately", "suspended", "act now", "24 hours", "unauthorized access", "unusual activity", "will be closed", "verify now", "account will be locked", "urgent action required", "failure to act"]
    urgency_hits = [phrase for phrase in urgency_phrases if phrase in lower]
    if urgency_hits:
        findings.append(Finding(f"Contains urgency/threat language ({', '.join(urgency_hits[:3])})", min(30, 15 * len(urgency_hits)), "high"))

    sensitive_terms = ["password", "ssn", "social security", "credit card", "pin number", "account number", "verify your identity", "card number", "cvv"]
    sensitive_hits = [term for term in sensitive_terms if term in lower]
    if sensitive_hits:
        findings.append(Finding(f"Requests sensitive information ({', '.join(sensitive_hits[:3])})", 20, "high"))

    jackpot_terms = ["you have won", "congratulations", "claim your prize", "lottery", "free gift", "you've been selected"]
    if any(term in lower for term in jackpot_terms):
        findings.append(Finding('Contains "too good to be true" reward or prize language', 20, "high"))

    sender_match = re.search(r"^from:\s*.*?@([\w.-]+)", text, re.I | re.M)
    if sender_match:
        domain = sender_match.group(1).lower()
        brands = ["paypal", "apple", "microsoft", "amazon", "google", "netflix", "bank", "chase"]
        mentioned = next((brand for brand in brands if brand in lower), None)
        official_map = {
            "paypal": "paypal.com",
            "apple": "apple.com",
            "microsoft": "microsoft.com",
            "amazon": "amazon.com",
            "google": "google.com",
            "netflix": "netflix.com",
            "chase": "chase.com",
        }
        if mentioned and official_map.get(mentioned) and not domain.endswith(official_map[mentioned]):
            findings.append(Finding(f"Sender domain ({domain}) does not match the brand mentioned in the email", 25, "high"))
        free_mail = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]
        if mentioned and domain in free_mail:
            findings.append(Finding(f'Claims to represent "{mentioned}" but sent from a free consumer email domain', 20, "high"))

    url_matches = re.findall(r"https?://[^\s)\"']+", text) or []
    for link in url_matches[:3]:
        url_result = analyze_url(link)
        if url_result.score > 20:
            findings.append(Finding(f"Contains an embedded link with phishing indicators: {link[:45]}{'…' if len(link) > 45 else ''}", max(10, round(url_result.score * 0.4)), "high"))

    exclaims = len(re.findall(r"!", text))
    caps_words = len(re.findall(r"\b[A-Z]{4,}\b", text))
    if exclaims >= 2 or caps_words >= 2:
        findings.append(Finding("Excessive punctuation or capitalization, common in mass phishing campaigns", 8, "low"))
    if re.search(r"(open the attachment|attached invoice|attachment to verify|see attached file)", lower):
        findings.append(Finding("Uses an attachment as a lure to get the recipient to open a file", 10, "med"))
    if "click here" in lower:
        findings.append(Finding('Uses vague "click here" link text rather than a descriptive link', 6, "low"))

    score = min(100, sum(f.score for f in findings))
    findings.sort(key=lambda item: severity_rank(item.severity), reverse=True)
    return build_result(score, findings)


def build_result(score: int, findings: List[Finding], verdict: str = "", color: str = "", stamp: str = "", description: str = "") -> AnalysisResult:
    if not verdict:
        if score >= 55:
            verdict, color, stamp, description = "PHISHING DETECTED", "#F0524B", "PHISHING", "Multiple strong indicators of phishing were found. Do not click links, download attachments, or enter credentials."
        elif score >= 25:
            verdict, color, stamp, description = "SUSPICIOUS", "#E8A33D", "SUSPICIOUS", "Some indicators of phishing were found. Proceed with caution and verify through an official channel before acting."
        else:
            verdict, color, stamp, description = "LIKELY SAFE", "#3ECF8E", "CLEARED", "No significant phishing indicators were detected. Always stay alert regardless of the score."
    return AnalysisResult(score=score, findings=findings, verdict=verdict, color=color, stamp=stamp, description=description)
