# 🛡️ CYRA (Cyber Aura)
> **Your Proactive Multi-Agent Cybersecurity Assistant**

CYRA is a smart personal security assistant built using the Google Agent Development Kit (ADK) and Gemini 2.5 Flash. Unlike standard antivirus apps that only react after a virus is downloaded, CYRA works in the background to stop scams before you click them. It scans text messages, chat logs, phone call transcripts, and local device networks to catch phishing, fake links, and device vulnerabilities instantly.

---

## 🧠 1. Core Architecture (4-Agent Team)

CYRA divides its work among four specialized AI agents that work together in a simple workflow loop:

* Input Data -> Parser Agent -> Threat Intelligence Agent -> Device Integrity Agent -> User Notifier Agent

*   🕵️ Parser & Extractor Agent: Cleans up incoming text and extracts websites, links, and suspicious phrases for analysis.
*   🔬 Threat Intelligence Agent: Uses our local Model Context Protocol (MCP Server) to look up suspicious domains, look-alike links, and data-harvesting tricks.
*   💻 Device Integrity Agent: Monitors simulated local device parameters, open ports, and connected network metadata to intercept unauthorized remote execution setups.
*   📢 User Notifier Agent: Takes the security results and converts them into a friendly, clear Markdown alert banner so you know exactly what the danger is.

---

## 🛡️ 2. Main Security Features

*   🔗 Link Decrypter (Fake URLs & Phishing Links): Checks hidden redirects and flags dangerous or sketchy domains ending in .xyz, .top, or .click.
*   🔑 Privacy Guard (Stealing Personal Data): Watches out for tricky text messages that try to pressure you into sharing OTPs, passwords, or bank details.
*   🎙️ Call Transcript Scanner (Voice Scams & Fake Calls): Scans written text transcripts of phone calls to detect high-pressure threats like fake bank alerts or fake police calls.
*   🛡️ Proactive Device Scanner: Scans local device state, configurations, system health logs, and network connection ports to alert users of potential remote access exploits.

---

## 🛠️ 3. Modular Tools (app/tools.py)

CYRA uses five simple Python tools to analyze security risks:

*   scan_text_stream(message_text): The first filter. Looks for bad domains and scam words inside messages.
*   decrypt_link_redirects(url): Unmasks shortened or hidden URLs to reveal the real destination.
*   context_privacy_guard(message_text): Detects if someone or a message is asking for your private banking passwords.
*   analyze_call_transcript(transcript): Checks phone call texts for psychological pressure, fake urgency, or identity theft.
*   scan_local_device_state(): Simulates checking background system ports, suspicious open network channels, and active mock access permissions.

---

## 💻 4. Local Playground Testing

The system is fully tested and verified in the local ADK playground. When CYRA finds a phishing attack or a device risk, it automatically prints out a clear dashboard warning like this:

⚠️ CYRA WARNING ALERT ⚠️
----------------------------------------
🔷 CYRA SECURITY ALERT – Device Exploitation / Vulnerability Found
* RISK LEVEL: HIGH
* THREAT TYPE: Open Diagnostic Port / Remote Connection Exposure

📋 WHAT WAS FOUND:
* Local device monitoring tool detected an unsafe network port configuration.
* A simulation run indicated unauthorized incoming traffic trying to scan root system directories.

💡 WHY THIS IS DANGEROUS:
Leaving diagnostic ports unencrypted or open to public networks allows malicious actors to silently control your device assets and extract private logs.

---

## ⚡ 5. Setup & Installation

1. Install Dependencies: pip install -r requirements.txt
2. Set API Key: Add your GEMINI_API_KEY into your local environment file.
3. Run the CLI Playground: agents-cli playground
4. Test: Type or paste any suspicious text or simulate a device scan check to see CYRA block it live!
