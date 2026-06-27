# ruff: noqa
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
CYRA (Cyber Aura) Agent Skills / Tools
---------------------------------------
Four specialised detection functions that the CYRA agent calls to inspect
incoming chat messages or call transcripts for cybersecurity threats.

Pipeline:
  Agent 1 (Parser)  →  scan_text_stream / context_privacy_guard
  Agent 2 (Evaluator) →  decrypt_link_redirects
  Agent 3 (Notifier)  →  analyze_call_transcript  [final synthesis]
"""

import re
import urllib.parse
from typing import Optional

# ---------------------------------------------------------------------------
# Internal helpers / simulated threat database
# ---------------------------------------------------------------------------

# Simulated MCP-server-style local threat database
_MALICIOUS_DOMAINS: set[str] = {
    "free-prize-claim.xyz",
    "win-lottery-now.top",
    "urgent-kyc-update.click",
    "bank-login-verify.xyz",
    "reset-your-wallet.top",
    "irs-refund-portal.click",
    "gov-stimulus-check.xyz",
    "crypto-airdrop-claim.top",
    "fedex-track-parcel.click",
    "account-suspended-alert.xyz",
}

_PHISHING_SIGNATURES: list[str] = [
    r"verify\s+your\s+(account|identity|bank|card)",
    r"your\s+account\s+(has\s+been\s+)?(suspended|blocked|locked)",
    r"click\s+(here|below|now)\s+to\s+(verify|confirm|update|claim)",
    r"(immediate|urgent)\s+action\s+required",
    r"you\s+have\s+won\s+a?\s*(prize|lottery|reward)",
    r"send\s+your\s+(otp|pin|password|cvv)",
    r"share\s+your\s+(otp|pin|password|cvv)",
    r"enter\s+your\s+(otp|pin|password|cvv)",
    r"irs\s+(refund|payment)",
    r"stimulus\s+(check|payment)\s+available",
]

# Suspicious TLDs associated with cheap/abusive domains
_SUSPICIOUS_TLDS: tuple[str, ...] = (
    ".xyz", ".top", ".click", ".tk", ".ml", ".cf", ".gq", ".pw",
    ".zip", ".mov", ".cam", ".icu", ".vip", ".monster",
)

# URL shorteners / redirect services
_URL_SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "short.io",
}

# Social-engineering urgency keywords
_URGENCY_KEYWORDS: list[str] = [
    "jail", "police", "arrest", "legal action", "court", "fbi", "cia",
    "immediate", "urgent", "right now", "act now", "expire", "expires",
    "suspended", "blocked", "criminal", "warrant", "penalty", "fine",
    "last warning", "last chance", "limited time", "account closed",
]

# Financial / identity data markers
_FINANCIAL_IDENTITY_PATTERNS: list[str] = [
    r"\botp\b", r"\bpin\b", r"\bcvv\b", r"\bpassword\b", r"\bpasscode\b",
    r"\bsocial\s+security\b", r"\bssn\b", r"\baadhar\b", r"\baadhaar\b",
    r"\bpan\s+(card|number)\b",
    r"\bcredit\s+card\b", r"\bdebit\s+card\b", r"\bcard\s+number\b",
    r"\baccount\s+number\b", r"\bifsc\b", r"\bswift\s+code\b",
    r"\bbank\s+detail", r"\bwallet\s+(address|key|seed)\b",
    r"\bprivate\s+key\b", r"\bseed\s+phrase\b", r"\brecovery\s+phrase\b",
]

# ---------------------------------------------------------------------------
# Tool 1: scan_text_stream
# ---------------------------------------------------------------------------

def scan_text_stream(message_text: str) -> dict:
    """Scan an incoming chat/text message for cybersecurity threat indicators.

    Performs regex and string analysis to detect:
    - Suspicious TLDs in embedded links (.xyz, .top, .click, etc.)
    - Credential-harvesting keywords (OTP, PIN, password, etc.)
    - Known phishing sentence patterns
    - Domains matching the local threat intelligence database

    Args:
        message_text: The raw text of a chat message, SMS, or email body
                      that needs to be scanned for threats.

    Returns:
        A dict with keys:
          - threat_detected (bool): True if any indicator was found.
          - risk_level (str): "HIGH", "MEDIUM", or "SAFE".
          - indicators (list[str]): Human-readable list of triggered signals.
          - raw_domains (list[str]): Any domain/URL tokens extracted from text.
    """
    text_lower = message_text.lower()
    indicators: list[str] = []
    raw_domains: list[str] = []

    # Extract all URL-like tokens
    url_pattern = re.compile(
        r"(https?://[^\s\"'<>]+|www\.[^\s\"'<>]+|[a-zA-Z0-9.-]+\.(xyz|top|click|tk|ml|cf|gq|pw|zip|mov|cam|icu|vip|monster)[^\s]*)",
        re.IGNORECASE,
    )
    matches = url_pattern.findall(message_text)
    for match in matches:
        token = match[0] if isinstance(match, tuple) else match
        raw_domains.append(token)

    # Check suspicious TLDs
    for domain in raw_domains:
        for tld in _SUSPICIOUS_TLDS:
            if domain.lower().endswith(tld) or f"{tld}/" in domain.lower():
                indicators.append(f"Suspicious TLD detected: '{domain}'")
                break

    # Check against known malicious domain DB
    for domain in raw_domains:
        parsed = domain.lower().replace("https://", "").replace("http://", "").split("/")[0]
        if parsed in _MALICIOUS_DOMAINS:
            indicators.append(f"KNOWN MALICIOUS DOMAIN in threat DB: '{parsed}'")

    # Check phishing signature patterns
    for pattern in _PHISHING_SIGNATURES:
        if re.search(pattern, text_lower):
            indicators.append(f"Phishing pattern matched: '{pattern}'")

    # Check credential keywords
    credential_keywords = ["otp", "pin", "password", "cvv", "passcode", "2fa code"]
    for kw in credential_keywords:
        if kw in text_lower:
            indicators.append(f"Credential keyword found: '{kw}'")

    # Determine risk level
    if any("KNOWN MALICIOUS" in i or "Phishing pattern" in i for i in indicators):
        risk_level = "HIGH"
    elif indicators:
        risk_level = "MEDIUM"
    else:
        risk_level = "SAFE"

    return {
        "threat_detected": risk_level != "SAFE",
        "risk_level": risk_level,
        "indicators": indicators,
        "raw_domains": raw_domains,
    }


# ---------------------------------------------------------------------------
# Tool 2: decrypt_link_redirects
# ---------------------------------------------------------------------------

def decrypt_link_redirects(url: str) -> dict:
    """Analyse a URL or shortened link to detect downstream malicious destinations.

    Performs multi-layer inspection:
    - Detects known URL shorteners that may mask the true destination.
    - Checks the final resolved domain against the threat intelligence DB.
    - Inspects URL query parameters for harvesting patterns (redirect=, next=, url=).
    - Checks for homograph / typo-squatting patterns on common brand names.

    Note: This tool performs simulated resolution. In production it would
    follow HTTP redirects. Here it analyses structural patterns instead.

    Args:
        url: The URL string to inspect. May be a full URL, shortened link,
             or bare domain name.

    Returns:
        A dict with keys:
          - is_malicious (bool): True if the link is likely malicious.
          - risk_level (str): "HIGH", "MEDIUM", or "SAFE".
          - findings (list[str]): Human-readable analysis results.
          - simulated_destination (str): Best guess at the true destination.
    """
    findings: list[str] = []
    url_clean = url.strip()

    # Normalise
    if not url_clean.startswith(("http://", "https://")):
        url_clean = "https://" + url_clean

    try:
        parsed = urllib.parse.urlparse(url_clean)
        domain = parsed.netloc.lower().lstrip("www.")
        path = parsed.path.lower()
        query = parsed.query.lower()
    except Exception:
        return {
            "is_malicious": False,
            "risk_level": "SAFE",
            "findings": ["Could not parse URL."],
            "simulated_destination": url,
        }

    simulated_destination = domain

    # 1. Check URL shorteners
    if domain in _URL_SHORTENERS:
        findings.append(
            f"URL shortener detected ('{domain}'). True destination is hidden — treat as HIGH RISK."
        )
        simulated_destination = f"[Hidden behind {domain}]"

    # 2. Check against known malicious DB
    if domain in _MALICIOUS_DOMAINS:
        findings.append(f"Domain '{domain}' found in MALICIOUS THREAT DATABASE.")

    # 3. Check suspicious TLDs
    for tld in _SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            findings.append(f"Suspicious TLD '{tld}' in domain '{domain}'.")
            break

    # 4. Check for redirect query parameters (open-redirect abuse)
    redirect_params = ["redirect", "next", "url", "return", "goto", "target", "dest"]
    for param in redirect_params:
        if re.search(rf"(^|&){param}=", query):
            findings.append(
                f"Redirect parameter '?{param}=' found — possible open-redirect attack."
            )

    # 5. Homograph / typo-squatting detection on popular brands
    brand_patterns = {
        "paypa1": "PayPal",
        "paypai": "PayPal",
        "arnazon": "Amazon",
        "amaz0n": "Amazon",
        "g00gle": "Google",
        "g0ogle": "Google",
        "micros0ft": "Microsoft",
        "rn icrosoft": "Microsoft",
        "netfl1x": "Netflix",
        "netf1ix": "Netflix",
        "faceb00k": "Facebook",
        "facebok": "Facebook",
        "bankofamerica-": "Bank of America",
        "chase-": "Chase Bank",
        "citibank-": "Citibank",
    }
    for spoof, brand in brand_patterns.items():
        if spoof in domain:
            findings.append(f"Possible typo-squatting / homograph of '{brand}': '{domain}'.")

    # 6. Path contains suspicious keywords
    suspicious_path_keywords = [
        "login", "signin", "verify", "confirm", "update", "secure",
        "bank", "account", "payment", "invoice", "claim",
    ]
    for kw in suspicious_path_keywords:
        if kw in path:
            findings.append(f"Suspicious keyword '{kw}' found in URL path.")
            break

    # Determine risk level
    if any(
        "MALICIOUS THREAT DATABASE" in f or "URL shortener" in f or "typo-squatting" in f
        for f in findings
    ):
        risk_level = "HIGH"
    elif findings:
        risk_level = "MEDIUM"
    else:
        risk_level = "SAFE"

    return {
        "is_malicious": risk_level != "SAFE",
        "risk_level": risk_level,
        "findings": findings if findings else ["No suspicious patterns found."],
        "simulated_destination": simulated_destination,
    }


# ---------------------------------------------------------------------------
# Tool 3: context_privacy_guard
# ---------------------------------------------------------------------------

def context_privacy_guard(message_text: str) -> dict:
    """Detect if a message is attempting to extract private financial or identity data.

    Triggers an immediate PRIVACY RISK marker when it identifies that the
    message is soliciting or referencing sensitive personal information such as:
    - Banking credentials (card numbers, account numbers, CVV, OTP)
    - Government identity numbers (SSN, Aadhaar, PAN)
    - Crypto private keys / seed phrases
    - Passwords or passcodes

    Args:
        message_text: The raw text of the message to analyse.

    Returns:
        A dict with keys:
          - privacy_risk (bool): True if personal data extraction is suspected.
          - risk_level (str): "HIGH", "MEDIUM", or "SAFE".
          - triggered_patterns (list[str]): Which privacy patterns were matched.
          - recommendation (str): A plain-language safety recommendation.
    """
    text_lower = message_text.lower()
    triggered: list[str] = []

    for pattern in _FINANCIAL_IDENTITY_PATTERNS:
        if re.search(pattern, text_lower):
            triggered.append(pattern.replace(r"\b", "").replace("\\", "").replace("s+", " ").strip())

    # Also flag messages that combine a request verb with a data type
    request_verbs = ["share", "send", "enter", "provide", "give", "type", "submit", "confirm"]
    data_types = ["otp", "pin", "password", "cvv", "card", "account", "aadhaar", "ssn", "pan"]
    for verb in request_verbs:
        for dtype in data_types:
            if verb in text_lower and dtype in text_lower:
                combo = f"Action combo: '{verb}' + '{dtype}'"
                if combo not in triggered:
                    triggered.append(combo)

    if triggered:
        risk_level = "HIGH"
        recommendation = (
            "⚠️ STOP — Do NOT share any personal, financial, or identity information. "
            "No legitimate organisation (bank, government, courier) will ever ask for your "
            "OTP, PIN, CVV, or full card number via chat or SMS. Hang up or ignore this message."
        )
    else:
        risk_level = "SAFE"
        recommendation = "No privacy extraction attempt detected in this message."

    return {
        "privacy_risk": risk_level != "SAFE",
        "risk_level": risk_level,
        "triggered_patterns": triggered,
        "recommendation": recommendation,
    }


# ---------------------------------------------------------------------------
# Tool 4: analyze_call_transcript
# ---------------------------------------------------------------------------

def analyze_call_transcript(transcript: str) -> dict:
    """Analyse a chat or call transcript for social engineering and deepfake scams.

    Scans for high-urgency language patterns that are hallmarks of:
    - Impersonation scams (police, IRS, bank official, tech support)
    - Vishing (voice phishing) attacks
    - Audio deepfake / AI-generated voice scam text representations
    - Romance or investment scams ("pig butchering")

    Args:
        transcript: The full text of a call transcript or multi-message
                    conversation thread to be analysed.

    Returns:
        A dict with keys:
          - scam_detected (bool): True if scam indicators are present.
          - risk_level (str): "HIGH", "MEDIUM", or "SAFE".
          - scam_type (str): Identified scam category or "Unknown" if mixed signals.
          - urgency_keywords_found (list[str]): Specific high-risk terms matched.
          - threat_summary (str): Plain-English summary of the threat.
    """
    text_lower = transcript.lower()
    found_keywords: list[str] = []

    for kw in _URGENCY_KEYWORDS:
        if kw in text_lower:
            found_keywords.append(kw)

    # Classify scam type based on keyword clusters
    scam_type = "Unknown"
    impersonation_signals = ["police", "cia", "fbi", "officer", "detective", "government", "irs", "court", "warrant", "arrest"]
    tech_support_signals = ["microsoft", "apple", "google", "virus", "hacked", "remote access", "teamviewer", "anydesk"]
    investment_signals = ["investment", "return", "profit", "crypto", "bitcoin", "guaranteed", "double your money"]
    romance_signals = ["darling", "sweetheart", "i love you", "gift", "stuck abroad", "need money", "emergency transfer"]

    if any(s in text_lower for s in impersonation_signals):
        scam_type = "Government / Law Enforcement Impersonation Scam"
    elif any(s in text_lower for s in tech_support_signals):
        scam_type = "Tech Support Scam"
    elif any(s in text_lower for s in investment_signals):
        scam_type = "Investment / Crypto Fraud"
    elif any(s in text_lower for s in romance_signals):
        scam_type = "Romance / Emergency Scam"
    elif found_keywords:
        scam_type = "Generic Social Engineering / Urgency Scam"

    # Determine risk level
    if len(found_keywords) >= 3 or scam_type != "Unknown":
        risk_level = "HIGH"
    elif found_keywords:
        risk_level = "MEDIUM"
    else:
        risk_level = "SAFE"

    # Generate threat summary
    if risk_level == "SAFE":
        threat_summary = "No social engineering or scam patterns detected in this transcript."
    else:
        threat_summary = (
            f"This transcript shows strong indicators of a '{scam_type}'. "
            f"Urgency signals detected: {', '.join(found_keywords[:5])}. "
            "This is a common tactic where scammers create panic to bypass rational thinking. "
            "Do NOT comply with any requests for money, gift cards, or personal information. "
            "End the call immediately and report it."
        )

    return {
        "scam_detected": risk_level != "SAFE",
        "risk_level": risk_level,
        "scam_type": scam_type if scam_type != "Unknown" else "N/A",
        "urgency_keywords_found": found_keywords,
        "threat_summary": threat_summary,
    }
