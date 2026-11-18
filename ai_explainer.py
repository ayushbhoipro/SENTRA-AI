import json
import os
from dotenv import load_dotenv
from google import genai


load_dotenv()

import streamlit as st

client = genai.Client(
    api_key=st.secrets["GEMINI_API_KEY"]
)

# Load report

with open("security_report.json") as file:
    report = json.load(file)



prompt = f"""

You are a cybersecurity analyst.

Analyze this APK security report.

Rules:
- Do not change the risk score.
- Do not create a new score.
- Explain the existing analysis.

Provide:

1. Risk explanation
2. Important findings
3. Security impact
4. Recommendations

Report:

{json.dumps(report, indent=2)}

"""


response = client.models.generate_content(
    model="gemini-3.6-flash",
    contents=prompt
)


ai_text = response.text


# Save AI result into report

report["ai_explanation"] = ai_text


with open("security_report.json","w") as file:
    json.dump(
        report,
        file,
        indent=4
    )


print("========== AI SECURITY EXPLANATION ==========")

print(ai_text)