# 🛡 Swaroop DevAI-CyberSafe

> **AI-Powered Cybersecurity Threat Detection & Security Intelligence Platform**

Swaroop DevAI-CyberSafe is an AI-powered cybersecurity platform that helps security analysts detect suspicious activities from authentication logs, generate AI-driven security reports, and interact with cybersecurity knowledge through a RAG (Retrieval-Augmented Generation) chatbot.

---

## 🚀 Features

### 🔍 Threat Detection
- Upload authentication log files
- Detect suspicious login attempts
- Identify brute-force attacks
- Analyze authentication events
- AI-generated threat analysis

### 📊 Security Dashboard
- Threat overview
- Risk score
- Threat severity metrics
- Top attacking IPs
- Threat distribution charts
- AI security summary

### 🤖 AI Security Chat (RAG)
- Upload cybersecurity PDF documents
- Build a searchable knowledge base
- Ask cybersecurity-related questions
- Receive AI-powered answers based on uploaded documents

### 📄 Security Reports
- Executive security summary
- Threat statistics
- AI-generated recommendations
- Download professional PDF reports

---

# 🖥 Application Workflow

```text
Upload Log File
        │
        ▼
AI Threat Analysis
        │
        ▼
Security Dashboard
        │
        ├────────► Threat Detection
        │
        ├────────► AI Chat
        │
        └────────► PDF Report
```

---

# 🛠 Tech Stack

| Category | Technologies |
|----------|--------------|
| Language | Python |
| Frontend | Streamlit |
| LLM | Groq (Llama 3) |
| Framework | LangChain |
| Vector Database | ChromaDB |
| Embeddings | HuggingFace |
| Charts | Plotly |
| PDF Reports | ReportLab |
| Data Processing | Pandas |

---

# 📂 Project Structure

```text
Swaroop-DevAI-CyberSafe/
│
├── agents/
│   ├── threat_agent.py
│   ├── rag_agent.py
│   ├── report_agent.py
│
├── assets/
│   ├── style.css
│
├── utils/
│   ├── dashboard.py
│   ├── charts.py
│   ├── llm.py
│
├── data/
│   ├── uploads/
│   └── sample_logs/
│
├── reports/
│
├── app.py
├── requirements.txt
├── README.md
└── .gitignore
```

---

# ⚙ Installation

## Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/Swaroop-DevAI-CyberSafe.git

cd Swaroop-DevAI-CyberSafe
```

---

## Create Virtual Environment

### Windows

```bash
python -m venv venv

venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv venv

source venv/bin/activate
```

---

## Install Requirements

```bash
pip install -r requirements.txt
```

---

## Configure API Key

Create a `.env` file.

```text
GROQ_API_KEY=your_groq_api_key
```

Or if deploying on Streamlit Cloud, add the secret:

```toml
GROQ_API_KEY="your_groq_api_key"
```

---

# ▶ Run Application

```bash
streamlit run app.py
```

---

# 📖 How to Use

### Step 1

Upload an authentication log file.

### Step 2

Click **Analyze**.

### Step 3

View the generated dashboard.

### Step 4

Review detected threats.

### Step 5

Generate a security report.

### Step 6

Upload cybersecurity PDFs and interact with the AI chatbot.

---

# 📸 Screenshots

## Dashboard

_Add screenshot here_

---

## Threat Detection

_Add screenshot here_

---

## AI Chat

_Add screenshot here_

---

## Reports

_Add screenshot here_

---

# 📌 Sample Log

A sample authentication log is included for testing.

```text
data/sample_logs/sample_auth.log
```

---

# 🌟 Future Improvements

- VirusTotal Integration
- MITRE ATT&CK Mapping
- CVE Search
- AbuseIPDB Integration
- User Authentication
- SQLite Incident Database
- Email Alerts
- Real-time Monitoring
- Docker Support
- Cloud Deployment

---

# 👨‍💻 Developer

## Katta Sai Swaroop

AI/ML Engineer | GenAI Developer | Backend Developer

📧 Email: swaroopsai927@gmail.com

🔗 LinkedIn: https://linkedin.com/in/katta-sai-swaroop-24603538b

💻 GitHub: https://github.com/saiswaroop66

---

# 📄 License

This project is licensed under the MIT License.

---

# ⭐ Support

If you found this project useful, consider giving it a ⭐ on GitHub!

---

## 🛡 Swaroop DevAI-CyberSafe

**Protect • Detect • Analyze • Secure**
