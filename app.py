import streamlit as st
import pandas as pd
import re
import matplotlib.pyplot as plt
from PyPDF2 import PdfReader
from openai import OpenAI

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
# ==================================================
# OMNIROUTE AI
# ==================================================

client = OpenAI(
    base_url="http://localhost:20128/v1",
    api_key="dummy"
)

MODEL = "auto/best-coding"


# ==================================================
# PAGE SETUP
# ==================================================

st.set_page_config(
    page_title="Sensitive Data Compliance Assistant",
    page_icon="🔐",
    layout="wide"
)

st.title("🔐 Sensitive Data Detection & Compliance Assistant")

st.write(
    "Upload a PDF, TXT, or CSV file to detect sensitive information."
)


# ==================================================
# READ DOCUMENT
# ==================================================

def extract_text(file):

    file_type = file.name.lower().split(".")[-1]

    if file_type == "pdf":

        reader = PdfReader(file)

        text = ""

        for page in reader.pages:

            page_text = page.extract_text()

            if page_text:
                text += page_text + "\n"

        return text

    elif file_type == "txt":

        return file.read().decode(
            "utf-8",
            errors="ignore"
        )

    elif file_type == "csv":

        df = pd.read_csv(file)

        return df.to_string(index=False)

    return ""


# ==================================================
# SENSITIVE DATA PATTERNS
# ==================================================

PATTERNS = {

    "Aadhaar Number": {
        "pattern": r"\b\d{4}\s?\d{4}\s?\d{4}\b",
        "risk": "High"
    },

    "PAN Number": {
        "pattern": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
        "risk": "High"
    },

    "Email Address": {
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "risk": "Medium"
    },

    "Phone Number": {
        "pattern": r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b",
        "risk": "Medium"
    },

    "Employee ID": {
        "pattern": r"\bEMP[-_]?\d{3,8}\b",
        "risk": "Medium"
    },

    "IFSC Code": {
        "pattern": r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
        "risk": "High"
    },

    "Password": {
        "pattern": r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*\S+",
        "risk": "High"
    },

    "Address": {
        "pattern": r"(?im)\b(?:address|residential address|home address)\s*[:=-]\s*[^\n,]+(?:,\s*[^\n]+){0,3}",
        "risk": "Low"
    },

    "Credit Card Number": {
        "pattern": r"\b(?:\d[ -]*?){13,19}\b",
        "risk": "High"
    },

    "Bank Account Number": {
        "pattern": r"(?i)\b(?:account number|account no|a/c no)\s*[:=-]?\s*\d{9,18}\b",
        "risk": "High"
    },

    "API Key": {
        "pattern": r"(?i)\b(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*[A-Za-z0-9_\-]{16,}\b",
        "risk": "High"
    },

    "Confidential Business Information": {
        "pattern": r"(?i)\b(?:confidential|internal use only|private|proprietary information|trade secret)\b",
        "risk": "Medium"
    }
}
# ==================================================
# DETECTION
# ==================================================

def detect_sensitive_data(text):

    findings = []

    for data_type, rule in PATTERNS.items():

        matches = re.findall(
            rule["pattern"],
            text
        )

        for match in matches:

            findings.append({
                "Type": data_type,
                "Value": match,
                "Risk": rule["risk"]
            })

    return findings


# ==================================================
# MASKING
# ==================================================

def mask_value(value, data_type):

    if data_type == "Aadhaar Number":

        digits = re.sub(r"\D", "", value)

        return "**** **** " + digits[-4:]


    elif data_type == "PAN Number":

        return value[0] + "****" + value[-4:]


    elif data_type == "Email Address":

        parts = value.split("@")

        username = parts[0]

        if len(username) > 1:

            masked_username = username[0] + "***"

        else:

            masked_username = "***"

        return masked_username + "@" + parts[1]


    elif data_type == "Phone Number":

        digits = re.sub(r"\D", "", value)

        return "******" + digits[-4:]


    elif data_type == "Employee ID":

        return "EMP-****"


    elif data_type == "IFSC Code":

        return value[:4] + "0****"


    elif data_type == "Password":

        return "********"


    elif data_type == "Address":

        return "[ADDRESS MASKED]"


    return "********"


# ==================================================
# UPLOAD
# ==================================================

uploaded_file = st.file_uploader(
    "📄 Upload your document",
    type=["pdf", "txt", "csv"]
)


# ==================================================
# PROCESS DOCUMENT
# ==================================================

findings = []
df = pd.DataFrame()
high = 0
medium = 0
low = 0
total = 0


if uploaded_file:

    st.success(
        f"Uploaded: {uploaded_file.name}"
    )

    text = extract_text(uploaded_file)

    if not text.strip():

        st.warning(
            "No readable text was found."
        )

    else:

        findings = detect_sensitive_data(text)

        st.subheader("📊 Detection Results")

        if findings:

            df = pd.DataFrame(findings)

            high = len(
                df[df["Risk"] == "High"]
            )

            medium = len(
                df[df["Risk"] == "Medium"]
            )

            low = len(
                df[df["Risk"] == "Low"]
            )

            total = len(df)


            # ==================================================
            # RISK DASHBOARD
            # ==================================================

            col1, col2, col3, col4 = st.columns(4)

            col1.metric(
                "📊 Total Findings",
                total
            )

            col2.metric(
                "🔴 High Risk",
                high
            )

            col3.metric(
                "🟠 Medium Risk",
                medium
            )

            col4.metric(
                "🟢 Low Risk",
                low
            )


            # ==================================================
            # OVERALL DOCUMENT RISK
            # ==================================================

            if high > 0:

                overall_risk = "🔴 HIGH RISK"

                risk_message = (
                    "High-risk sensitive information was detected. "
                    "Immediate security controls are recommended."
                )

            elif medium > 0:

                overall_risk = "🟠 MEDIUM RISK"

                risk_message = (
                    "Medium-risk sensitive information was detected. "
                    "Additional security controls are recommended."
                )

            elif low > 0:

                overall_risk = "🟢 LOW RISK"

                risk_message = (
                    "Only low-risk information was detected."
                )

            else:

                overall_risk = "⚪ NO RISK DETECTED"

                risk_message = (
                    "No sensitive information was detected."
                )


            st.subheader("📋 Overall Document Risk")

            st.metric(
                "Document Risk Level",
                overall_risk
            )

            st.info(
                risk_message
            )

            # ==================================================
            # RISK DISTRIBUTION CHART
            # ==================================================

            st.subheader("📈 Risk Distribution")

            risk_data = pd.DataFrame({
                "Risk Level": ["High", "Medium", "Low"],
                "Count": [high, medium, low]
            })

            fig, ax = plt.subplots()

            ax.bar(
                risk_data["Risk Level"],
                risk_data["Count"]
            )

            ax.set_xlabel("Risk Level")
            ax.set_ylabel("Number of Findings")
            ax.set_title("Sensitive Data Risk Distribution")

            st.pyplot(fig)


            # ==================================================
            # DATA TYPE DISTRIBUTION
            # ==================================================

            st.subheader("📊 Sensitive Data Type Distribution")

            type_counts = df["Type"].value_counts()

            fig2, ax2 = plt.subplots()

            ax2.bar(
                type_counts.index,
                type_counts.values
            )

            ax2.set_xlabel("Sensitive Data Type")
            ax2.set_ylabel("Number of Findings")
            ax2.set_title("Sensitive Data Type Distribution")

            plt.xticks(
                rotation=45,
                ha="right"
            )

            st.pyplot(fig2)


            # ==================================================
            # DETECTION TABLE
            # ==================================================

            st.dataframe(
                df,
                width="stretch"
            )
            
            # ==================================================
            # DOWNLOAD RESULTS
            # ==================================================

            csv_data = df.to_csv(index=False).encode("utf-8")

            st.download_button(
                label="📥 Download Detection Results",
                data=csv_data,
                file_name="sensitive_data_results.csv",
                mime="text/csv"
            )
            # ==================================================
            # MASK BUTTON
            # ==================================================

            if st.button("🛡️ Mask Sensitive Data"):

                masked_df = df.copy()

                masked_df["Value"] = masked_df.apply(
                    lambda row: mask_value(
                        row["Value"],
                        row["Type"]
                    ),
                    axis=1
                )

                st.subheader(
                    "🛡️ Masked Sensitive Data"
                )

                st.dataframe(
                    masked_df,
                    width="stretch"
                )


        else:

            st.success(
                "✅ No sensitive information detected."
            )


# ==================================================
# AI COMPLIANCE SUMMARY
# ==================================================

if uploaded_file and findings:

    st.divider()

    st.subheader(
        "🤖 AI Compliance Summary"
    )

    if st.button(
        "✨ Generate AI Compliance Summary"
    ):

        with st.spinner(
            "AI is analyzing the detected sensitive data..."
        ):

            try:

                summary_prompt = f"""
You are a cybersecurity and data-compliance assistant.

Analyze the following sensitive-data detection results.

Detected data:

{df[['Type', 'Risk']].to_string(index=False)}

Statistics:

Total findings: {total}
High-risk findings: {high}
Medium-risk findings: {medium}
Low-risk findings: {low}

Prepare a clear compliance report with exactly these sections:

1. Compliance Observations
2. Security Risks
3. Remediation Steps

Explain the findings in simple professional language.

Do not repeat or expose any actual sensitive values.

Use bullet points where appropriate.
"""

                response = client.chat.completions.create(
                    model=MODEL,
                    messages=[
                        {
                            "role": "system",
                            "content": "You are a cybersecurity compliance expert."
                        },
                        {
                            "role": "user",
                            "content": summary_prompt
                        }
                    ],
                    temperature=0.2,
                    stream=True
                )

                ai_summary = ""

                for chunk in response:

                    if chunk.choices:

                        delta = chunk.choices[0].delta

                        if delta.content:

                            ai_summary += delta.content

                if ai_summary.strip():

                    st.success(
                        "✅ AI analysis completed!"
                    )

                    st.markdown(
                        ai_summary
                    )

                else:

                    st.warning(
                        "⚠️ AI returned an empty response."
                    )

            except Exception as e:

                st.error(
                    f"AI Summary Error: {e}"
                )


# ==================================================

# ASK QUESTIONS

# ==================================================

if uploaded_file and findings:

    st.divider()

    st.subheader("💬 Ask Questions About Your Document")

    question = st.text_input(
       "Ask a question about the detected sensitive data:",
        placeholder="Example: How many email addresses were detected?"
)

if st.button("🔎 Ask AI"):

    if not question.strip():

        st.warning("Please enter a question.")

    else:

        with st.spinner("AI is analyzing your question..."):

            try:

                question_prompt = f"""


You are a cybersecurity compliance assistant.

Detection statistics:

Total findings: {total}
High-risk findings: {high}
Medium-risk findings: {medium}
Low-risk findings: {low}

Detected data types:

{df[['Type', 'Risk']].to_string(index=False)}

Answer the user's question using ONLY the detection results.

Rules:

* Count matching rows when asked "how many".
* Email Address means email.
* Phone Number means phone number.
* Aadhaar Number means Aadhaar.
* PAN Number means PAN.
* Employee ID means employee ID.
* IFSC Code means IFSC.
* Password means password.
* Do not confuse email address with physical postal address.
* Never reveal actual sensitive values.
* If information is not present, say so clearly.

User question:

{question}

Give a short, clear and professional answer.
"""


                response = client.chat.completions.create(
                    model=MODEL,
                    messages=[
                        {
                            "role": "system",
                            "content": "You are a cybersecurity compliance expert."
                        },
                        {
                            "role": "user",
                            "content": question_prompt
                        }
                    ],
                    temperature=0.2,
                    stream=True
                )

                answer = ""

                for chunk in response:

                    if chunk.choices:

                        delta = chunk.choices[0].delta

                        if delta.content:

                            answer += delta.content

                if answer.strip():

                    st.success("✅ Answer")

                    st.markdown(answer)

                else:

                    st.warning(
                        "⚠️ AI returned an empty response."
                    )

            except Exception as e:

                st.error(
                    f"Question Answering Error: {e}"
                )


# ==================================================

# DOWNLOAD COMPLIANCE REPORT

# ==================================================
if uploaded_file and findings:

    st.divider()

    st.subheader("📄 Download Compliance Report")

    report_text = f"""
SENSITIVE DATA DETECTION & COMPLIANCE REPORT
=============================================

File Name:
{uploaded_file.name}

SUMMARY
-------
Total Findings: {total}
High Risk: {high}
Medium Risk: {medium}
Low Risk: {low}


DETECTED DATA TYPES
-------------------

"""

    for data_type, count in df["Type"].value_counts().items():

        report_text += f"- {data_type}: {count}\n"


    report_text += """

RISK DISTRIBUTION
-----------------
"""

    report_text += f"- High Risk: {high}\n"
    report_text += f"- Medium Risk: {medium}\n"
    report_text += f"- Low Risk: {low}\n"


    report_text += """

SECURITY RECOMMENDATIONS
------------------------

1. Protect all high-risk sensitive information.
2. Do not store passwords in plain text.
3. Use masking when displaying sensitive data.
4. Restrict access using least-privilege principles.
5. Encrypt sensitive information.
6. Regularly audit systems for sensitive-data exposure.
7. Use multi-factor authentication.
8. Follow applicable data-protection requirements.


DISCLAIMER
----------

This report is based on automated detection results.
The results should be manually verified by security
and compliance teams.
"""


    st.download_button(
        label="📥 Download Compliance Report",
        data=report_text,
        file_name="compliance_report.txt",
        mime="text/plain"
    )

# ==================================================
# DOWNLOAD PDF COMPLIANCE REPORT
# ==================================================

if uploaded_file and findings:

    st.divider()

    st.subheader("📄 Download PDF Compliance Report")

    pdf_path = "compliance_report.pdf"

    c = canvas.Canvas(
        pdf_path,
        pagesize=A4
    )

    width, height = A4

    y = height - 50

    # --------------------------------------------------
    # TITLE
    # --------------------------------------------------

    c.setFont(
        "Helvetica-Bold",
        16
    )

    c.drawString(
        50,
        y,
        "Sensitive Data Detection & Compliance Report"
    )

    y -= 40

    # --------------------------------------------------
    # FILE INFORMATION
    # --------------------------------------------------

    c.setFont(
        "Helvetica",
        11
    )

    c.drawString(
        50,
        y,
        f"File Name: {uploaded_file.name}"
    )

    y -= 30

    c.drawString(
        50,
        y,
        f"Total Findings: {total}"
    )

    y -= 20

    c.drawString(
        50,
        y,
        f"High Risk: {high}"
    )

    y -= 20

    c.drawString(
        50,
        y,
        f"Medium Risk: {medium}"
    )

    y -= 20

    c.drawString(
        50,
        y,
        f"Low Risk: {low}"
    )

    y -= 40

    # --------------------------------------------------
    # DETECTED DATA TYPES
    # --------------------------------------------------

    c.setFont(
        "Helvetica-Bold",
        12
    )

    c.drawString(
        50,
        y,
        "Detected Data Types"
    )

    y -= 25

    c.setFont(
        "Helvetica",
        10
    )

    for data_type, count in df["Type"].value_counts().items():

        c.drawString(
            60,
            y,
            f"- {data_type}: {count}"
        )

        y -= 18

        if y < 60:

            c.showPage()

            y = height - 50

            c.setFont(
                "Helvetica",
                10
            )

    # --------------------------------------------------
    # SECURITY RECOMMENDATIONS
    # --------------------------------------------------

    y -= 20

    c.setFont(
        "Helvetica-Bold",
        12
    )

    c.drawString(
        50,
        y,
        "Security Recommendations"
    )

    y -= 25

    c.setFont(
        "Helvetica",
        10
    )

    recommendations = [
        "Protect all high-risk sensitive information.",
        "Do not store passwords in plain text.",
        "Use masking when displaying sensitive data.",
        "Restrict access using least-privilege principles.",
        "Encrypt sensitive information.",
        "Regularly audit systems for sensitive-data exposure.",
        "Use multi-factor authentication.",
        "Follow applicable data-protection requirements."
    ]

    for recommendation in recommendations:

        c.drawString(
            60,
            y,
            f"- {recommendation}"
        )

        y -= 18

        if y < 60:

            c.showPage()

            y = height - 50

            c.setFont(
                "Helvetica",
                10
            )

    # --------------------------------------------------
    # SAVE PDF
    # --------------------------------------------------

    c.save()

    # --------------------------------------------------
    # DOWNLOAD BUTTON
    # --------------------------------------------------

    with open(
        pdf_path,
        "rb"
    ) as pdf_file:

        st.download_button(
            label="📥 Download PDF Report",
            data=pdf_file,
            file_name="compliance_report.pdf",
            mime="application/pdf"
        )

