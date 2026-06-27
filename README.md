# 🛡️ CYRA (Cyber Aura)
> **Your Proactive Multi-Agent Cybersecurity Assistant**

CYRA is a smart personal security assistant built using the Google Agent Development Kit (ADK) and Gemini 2.5 Flash. Unlike standard antivirus apps that only react after a virus is downloaded, CYRA works in the background to stop scams before you click them. It scans text messages, chat logs, and phone call transcripts to catch phishing, fake links, and social engineering tricks instantly.

---

## 🧠 1. Core Architecture (3-Agent Team)

CYRA divides its work among three specialized AI agents that work together in a simple workflow loop:

* Incoming Message/Text -> Parser Agent -> Threat Intelligence Agent -> User Notifier Agent

*   🕵️ Parser & Extractor Agent: Cleans up incoming text and extracts websites, links, and suspicious phrases for analysis.
*   🔬 Threat Intelligence Agent: Uses our local Model Context Protocol (MCP Server) to look up suspicious domains, look-alike links, and data-harvesting tricks.
*   📢 User Notifier Agent: Takes the security results and converts them into a friendly, clear Markdown alert banner so you know exactly what the danger is.

---

## 🛡️ 2. Main Security Features

*   🔗 Link Decrypter (Fake URLs & Phishing Links): Checks hidden redirects and flags dangerous or sketchy domains ending in .xyz, .top, or .click.
*   🔑 Privacy Guard (Stealing Personal Data): Watches out for tricky text messages that try to pressure you into sharing OTPs, passwords, or bank details.
*   🎙️ Call Transcript Scanner (Voice Scams & Fake Calls): Scans written text transcripts of phone calls to detect high-pressure threats like fake bank alerts or fake police calls.

---

## 🛠️ 3. Modular Tools (app/tools.py)

CYRA uses four simple Python tools to analyze security risks:

*   scan_text_stream(message_text): The first filter. Looks for bad domains and scam words inside messages.
*   decrypt_link_redirects(url): Unmasks shortened or hidden URLs to reveal the real destination.
*   context_privacy_guard(message_text): Detects if someone or a message is asking for your private banking passwords.
*   analyze_call_transcript(transcript): Checks phone call texts for psychological pressure, fake urgency, or identity theft.

---

## 💻 4. Local Playground Testing

The system is fully tested and verified in the local ADK playground. When CYRA finds a phishing attack, it automatically prints out a clear dashboard warning like this:

⚠️ CYRA WARNING ALERT ⚠️
----------------------------------------
🔷 CYRA SECURITY ALERT – Phishing Lottery Scam
* RISK LEVEL: HIGH
* THREAT TYPE: Phishing Link / Data Theft / Social Engineering

📋 WHAT WAS FOUND:
* A dangerous website domain ending in .top (win-lottery-now.top) was detected.
* The text explicitly asks for your "bank account number", triggering our security shields.

💡 WHY THIS IS DANGEROUS:
This is a fake lottery scam trying to trick you into sharing your private financial info to steal money.

---

## ⚡ 5. Setup & Installation

1. Install Dependencies: pip install -r requirements.txt
2. Set API Key: Add your GEMINI_API_KEY into your local environment file.
3. Run the CLI Playground: agents-cli playground
4. Test: Type or paste any suspicious text or link to see CYRA block it live!
