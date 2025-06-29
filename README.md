# 📧 Email Packet Analyzer

The **Email Packet Analyzer** is a Python-based utility crafted to inspect `.pcapng` network capture files for email
communications and detect suspicious messages. It identifies threats based on predefined patterns in the email body,
malicious links, and dangerous attachments.

## 📂 Setup Instructions

1. **Add Packet Files**

   Place all `.pcapng` files you wish to analyze into the `PacketFiles/` directory.

## 🛠 Installation

Install the required Python dependencies using:

```bash
  pip3 install -r requirements.txt
```

## ▶️ Running the Analyzer

Run the tool with:

```bash
  python3 PacketAnalyzer.py
```

## 🧪 Features

- Analyzes email traffic over SMTP, IMAP, and POP protocols.
- Identifies and logs suspicious messages based on common phishing indicators.
- Generates a report for each analyzed session in the `AnalysisReports/` directory.
