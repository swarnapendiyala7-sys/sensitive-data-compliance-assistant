# 🔐 Sensitive Data Detection & Compliance Assistant

An AI-powered Streamlit application that detects sensitive and confidential information in documents, classifies security risk, generates compliance recommendations, and allows users to ask questions about detected data.

## 🚀 Features

* 📄 Upload PDF, TXT, and CSV documents
* 🔍 Detect sensitive information using Python Regular Expressions
* 🔐 Detect Aadhaar numbers, PAN numbers, email addresses, phone numbers, employee IDs, IFSC codes, passwords, addresses, credit card numbers, bank account numbers, API keys, and confidential business information
* ⚠️ Classify findings as Low, Medium, or High Risk
* 📊 Display risk and sensitive-data distribution dashboards
* 🤖 Generate AI-powered compliance observations, security risks, and remediation steps
* 💬 Ask questions about detected sensitive data
* 🛡️ Mask sensitive information before displaying it
* 📥 Download detection results as CSV
* 📄 Download compliance reports as TXT and PDF

## 🛠️ Technologies Used

* Python
* Streamlit
* Pandas
* Regular Expressions (Regex)
* PyPDF2
* Matplotlib
* OpenAI-compatible API
* ReportLab

## 🧠 AI/ML Approach

The application uses a combination of rule-based detection and AI.

### Sensitive Data Detection

Regular expressions are used to identify structured sensitive information such as:

* Aadhaar numbers
* PAN numbers
* Email addresses
* Phone numbers
* Employee IDs
* IFSC codes
* Passwords
* Credit card numbers
* Bank account numbers
* API keys

### Risk Classification

Each detected data type is assigned a risk level.

**High Risk**

* Aadhaar Number
* PAN Number
* Credit Card Number
* Bank Account Number
* API Key
* Password
* IFSC Code

**Medium Risk**

* Email Address
* Phone Number
* Employee ID
* Confidential Business Information

**Low Risk**

* Address

### AI Compliance Analysis

The detected results are sent to an AI model without exposing the actual sensitive values.

The AI generates:

1. Compliance observations
2. Security risks
3. Remediation steps

The application also provides an AI question-answering feature for questions such as:

* How many email addresses were detected?
* What sensitive data exists?
* What are the compliance risks?
* How many high-risk findings are present?

## 🏗️ Architecture Overview

```text
User
  │
  ▼
Streamlit Web Interface
  │
  ▼
Document Upload
(PDF / TXT / CSV)
  │
  ▼
Text Extraction
  │
  ▼
Regex Sensitive Data Detection
  │
  ▼
Risk Classification
  │
  ├──────────────► Risk Dashboard
  │
  ├──────────────► Data Masking
  │
  ├──────────────► CSV Report
  │
  ├──────────────► PDF Compliance Report
  │
  ▼
AI Compliance Analysis
  │
  ├──────────────► Compliance Summary
  │
  └──────────────► Question Answering
```

## ⚙️ Setup Instructions

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd sensitive-data-compliance-assistant
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

### 3. Activate the virtual environment

Windows:

```bash
.venv\Scripts\activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Start the application

```bash
streamlit run app.py
```

The application will open in your browser.

## 🔒 Security Considerations

* Sensitive values should not be exposed unnecessarily.
* The application provides masking functionality.
* AI prompts instruct the model not to reveal sensitive values.
* API keys and passwords should never be committed to GitHub.
* Production deployments should use environment variables or secure secrets management.
* Access to sensitive documents should be restricted.

## 📊 Example Workflow

1. Upload a PDF, TXT, or CSV file.
2. The application extracts the document text.
3. Regex patterns detect sensitive information.
4. Each finding receives a risk classification.
5. The dashboard displays the results.
6. The user can mask detected values.
7. AI generates a compliance summary.
8. The user can ask questions about the detected data.
9. The user can download CSV, TXT, or PDF reports.

## ⚠️ Limitations

* Regex-based detection may produce false positives or miss unusual formats.
* Scanned PDFs may require OCR support.
* AI-generated recommendations should be reviewed by security or compliance professionals.
* Production systems should implement stronger authentication, authorization, logging, and secure storage.

## 🚧 Challenges Faced

* Designing reliable regular expressions for different sensitive-data formats.
* Avoiding exposure of actual sensitive values in the user interface and AI prompts.
* Handling different document formats such as PDF, TXT, and CSV.
* Managing risk classification for different types of sensitive information.
* Integrating AI question answering with the detection results.
* Generating downloadable compliance reports.

## 🔮 Future Improvements

* OCR support for scanned documents
* RAG using FAISS or ChromaDB
* Multi-document analysis
* Advanced NLP and Named Entity Recognition
* Improved false-positive detection
* Audit logging
* User authentication and role-based access
* Dockerization
* Cloud deployment
* Automated compliance checks for regulations such as GDPR and applicable Indian data-protection requirements

## 📄 Disclaimer

This application is a prototype for sensitive-data detection and compliance assistance.

Automated detection results should be manually reviewed before making security or compliance decisions.
# sensitive-data-compliance-assistant
AI-powered Sensitive Data Detection &amp; Compliance Assistant
