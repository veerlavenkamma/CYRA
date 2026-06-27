# CYRA (Cyber Aura) - Proactive Multi-Agent Cybersecurity Concierge

CYRA is an advanced, proactive personal cybersecurity assistant built utilizing the Google Agent Development Kit (ADK) and Gemini 2.5 Flash. Unlike reactive anti-virus software, CYRA operates natively as an ambient intelligence layer that analyzes incoming text streams, social communication logs, and audio/text call transcripts to intercept social engineering, phishing, and identity extraction scams before a user interacts with them.

---

## 🧠 Core Architecture (3-Agent Orchestration Flow)

CYRA implements a decoupled Multi-Agent Routing Loop pattern where specialized modules reason over data contextually:

1. **Parser & Extractor Agent:** Natively handles incoming message payloads, stripping down complex text strings to isolate target links, structural patterns, and suspicious phrasing tokens.
2. **Threat Intelligence Agent:** Executes deep reasoning loops by passing extracted tokens against our Model Context Protocol (MCP Server) simulator—evaluating against active repositories of known hostile top-level domains, look-alike patterns, and credential-harvesting indicators.
3. **User Notifier Agent:** Consolidates the technical risk signals and structures a friendly, high-visibility Markdown warning banner tailored directly for end-user safety.

---

## 🛡️ Key Security Features (What Makes CYRA Stand Out)

### 1. Dynamic Link Decrypter (Fake URL Defense)
Traces the background behavior of shortened, masked, or look-alike domains. If an incoming message features deceptive links or suspicious Top-Level Domains (such as `.xyz`, `.top`, or `.click`), CYRA analyzes downstream paths to identify potential phishing loops and brand impersonation.

### 2. Context-Aware Privacy Guard
Monitors structural context for highly sensitive credential harvesting. If an attacker leverages conversational engineering to aggressively solicit a user's critical vectors—such as OTPs, account passwords, bank metrics, or identity card numbers—CYRA immediately Flags the risk signature.

### 3. Phishing Audio/Text Call Scanner
Designed specifically to tackle modern high-urgency and deepfake voice-to-text scams. It maps lexical semantic profiles within chat or call transcripts to instantly detect high-pressure intimidation phrases (e.g., immediate arrest, bank account blocked, or authority impersonator patterns).

---

## 🛠️ Modular Agent Skills (`app/tools.py`)

CYRA leverages four specialized Python-native tool structures to extract context:
*   `scan_text_stream(message_text)`: Core lexical filter targeting untrusted TLDs and aggressive keyword extractions.
*   `decrypt_link_redirects(url)`: Traces hidden hop paths and masked structural URLs.
*   `context_privacy_guard(message_text)`: Evaluates whether active queries are targeting credential architectures.
*   `analyze_call_transcript(transcript)`: Parses deepfake text layers for high-pressure timelines or authority impersonation language.

---

## 💻 Local Playground Verification Output

The system has been completely verified within the local interactive ADK framework environment. When an active phishing or extraction vector is processed, CYRA generates a dedicated Markdown warning:

```markdown
⚠️ CYRA WARNING ALERT ⚠️
----------------------------------------
🔷 CYRA SECURITY ALERT – Phishing Lottery Scam
🚨 RISK LEVEL: HIGH
🔍 THREAT TYPE: Phishing Link / Credential Harvesting / Social Engineering

📋 WHAT WAS FOUND: 
• A suspicious Top-Level Domain (.top) and a known malicious domain (win-lottery-now.top) were isolated.
• The payload explicitly solicits a "bank account number," triggering the credential protection layer.

💡 WHY THIS IS DANGEROUS: 
This is a high-pressure social engineering scam masquerading as a lottery reward to compromise individual banking data structures.
```
