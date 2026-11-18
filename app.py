import json
import os
import subprocess
import sys
from pathlib import Path

import streamlit as st


BASE_DIR = Path(__file__).resolve().parent
APK_PATH = BASE_DIR / "uploaded.apk"
REPORT_PATH = BASE_DIR / "security_report.json"
ANALYSIS_PATH = BASE_DIR / "analysis.json"


def run_step(command, input_text=None):
    return subprocess.run(
        command,
        cwd=BASE_DIR,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )


def load_json(path):
    with open(path, "r") as file:
        return json.load(file)


def risk_color(level):
    if level == "HIGH RISK":
        return "#ef4444"
    if level == "MEDIUM RISK":
        return "#f59e0b"
    return "#22c55e"


st.set_page_config(
    page_title="SENTRA AI",
    page_icon="shield",
    layout="wide",
)

if "scan_completed" not in st.session_state:
    st.session_state.scan_completed = False

st.markdown(
"""
<style>

.stApp {
    background:
    radial-gradient(circle at top left, #12304a 0%, transparent 35%),
    radial-gradient(circle at bottom right, #123b2c 0%, transparent 30%),
    #050b14;

    color:white;
}


/* Main container */
.block-container {
    max-width:1400px;
    padding-top:2rem;
}


/* HERO */

.hero {

    background:
    linear-gradient(
        135deg,
        rgba(15,23,42,0.95),
        rgba(20,35,50,0.75)
    );

    border:1px solid rgba(255,255,255,0.12);

    border-radius:25px;

    padding:50px;

    box-shadow:
    0 20px 60px rgba(0,0,0,.5);

}


.hero h1 {

    font-size:4rem;

    font-weight:900;

    letter-spacing:-2px;

}


.hero p {

    color:#9ca3af;

    font-size:1.2rem;

    max-width:700px;

}



/* Section headings */

.section-title {

font-size:1.5rem;

font-weight:800;

margin-top:35px;

}



/* Cards */

.metric-card {


background:
rgba(255,255,255,0.06);


backdrop-filter:blur(15px);


border:

1px solid rgba(255,255,255,.15);


border-radius:20px;


padding:25px;


height:140px;


box-shadow:
0 15px 40px rgba(0,0,0,.35);

}



.metric-label {

color:#94a3b8;

font-size:.9rem;

}



.metric-value {


font-size:2.4rem;

font-weight:900;

}



.metric-note {

color:#94a3b8;

font-size:.8rem;

}



/* panels */


.info-panel {


background:

rgba(255,255,255,.05);


border:

1px solid rgba(255,255,255,.12);


border-radius:20px;


padding:25px;


box-shadow:

0 15px 40px rgba(0,0,0,.4);

}



/* upload */


[data-testid="stFileUploader"] {


background:

rgba(255,255,255,.06);


border-radius:20px;


padding:20px;


}



/* button */


.stButton button {


background:

linear-gradient(
90deg,
#00d4ff,
#00ff88
);


border:none;


border-radius:15px;


height:3.5rem;


font-weight:900;


color:#001;


font-size:1.1rem;


}


.stButton button:hover {


transform:scale(1.02);


}


/* findings */


.finding {


background:

rgba(255,255,255,.06);


border-left:

4px solid #00d4ff;


padding:20px;


border-radius:15px;


margin-bottom:15px;


}



</style>
""",
unsafe_allow_html=True
)
 

st.markdown(
    """
    <div class="hero">
        <div class="eyebrow">Static APK analysis + deterministic risk engine + AI explanation</div>
        <h1>SENTRA AI</h1>
        <p>
Autonomous APK security intelligence platform.
Analyze permissions, APIs, network behaviour and
generate explainable threat reports.
</p>
    </div>
    """,
    unsafe_allow_html=True,
)

st.write("")

left, right = st.columns([0.42, 0.58], gap="large")

with left:
    st.markdown('<div class="section-title">Scan Input</div>', unsafe_allow_html=True)
    uploaded_file = st.file_uploader("Upload APK file", type=["apk"], label_visibility="collapsed")

    run_ai = st.toggle("Generate AI explanation", value=True)

    scan_clicked = st.button("Scan APK")

if uploaded_file:
    st.session_state.scan_completed = False

    file_size_kb = len(uploaded_file.getbuffer()) / 1024 

    st.markdown(
        f"""
        <div class="info-panel">
                <strong>{uploaded_file.name}</strong><br>
                <span class="muted">{file_size_kb:.1f} KB ready for analysis</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

with right:
    st.markdown('<div class="section-title">Pipeline</div>', unsafe_allow_html=True)
    st.markdown(
        """
        <div class="info-panel">
            <strong>1.</strong> Extract APK metadata, permissions, APIs, components, URLs<br>
            <strong>2.</strong> Calculate risk score with your rule engine<br>
            <strong>3.</strong> Add AI summary without changing the score
        </div>
        """,
        unsafe_allow_html=True,
    )


if scan_clicked:
    if not uploaded_file:
        st.error("Upload an APK file first.")
        st.stop()

    APK_PATH.write_bytes(uploaded_file.getbuffer())

    python_bin = sys.executable
    errors = []

    with st.status("Running APK security scan...", expanded=True) as status:
        st.write("Analyzing APK structure and permissions")
        analyzer = run_step([python_bin, "analyzer.py"], input_text=f"{APK_PATH.name}\n")
        if analyzer.returncode != 0:
            errors.append(("Analyzer failed", analyzer.stderr or analyzer.stdout))

        if not errors:
            st.write("Calculating deterministic risk score")
            risk = run_step([python_bin, "risk_engine.py"])
            if risk.returncode != 0:
                errors.append(("Risk engine failed", risk.stderr or risk.stdout))

        if not errors and run_ai:
            st.write("Generating AI explanation")
            ai = run_step([python_bin, "ai_explainer.py"])
            if ai.returncode != 0:
                errors.append(("AI explanation failed", ai.stderr or ai.stdout))

        if errors:
            status.update(label="Scan stopped", state="error")
        else:
            status.update(label="Scan complete", state="complete")
            st.session_state.scan_completed = True

    if errors:
        for title, detail in errors:
            st.error(title)
            with st.expander("Show details"):
                st.code(detail[-6000:])
        st.stop()


if REPORT_PATH.exists() and st.session_state.scan_completed:
    report = load_json(REPORT_PATH)
    analysis = load_json(ANALYSIS_PATH) if ANALYSIS_PATH.exists() else {}

    level = report.get("risk_level", "UNKNOWN")
    color = risk_color(level)
    findings = report.get("findings", [])
    behaviours = report.get("behaviours", [])
    score = report.get("risk_score", 0)
    ai_text = report.get("ai_explanation")

    st.markdown('<div class="section-title">Security Summary</div>', unsafe_allow_html=True)

    m1,m2,m3,m4 = st.columns(
    [1,1,1,1],
    gap="large"
)
    with m1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">Risk Score</div>
                <div class="metric-value">{score}/100</div>
                <div class="metric-note">Calculated by your engine</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with m2:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">Risk Level</div>
                <div class="metric-value" style="color:{color}; font-size:1.55rem;">{level}</div>
                <div class="metric-note">AI does not alter this</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with m3:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">Findings</div>
                <div class="metric-value">{len(findings)}</div>
                <div class="metric-note">Threat indicators</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with m4:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">Behaviours</div>
                <div class="metric-value">{len(behaviours)}</div>
                <div class="metric-note">Correlated signals</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.write("")

    app_col, tech_col = st.columns([0.46, 0.54], gap="large")

    with app_col:
        st.markdown('<div class="section-title">APK Information</div>', unsafe_allow_html=True)
        file_data = analysis.get("file", {})
        components = analysis.get("components", {})
        api_usage = analysis.get("api_usage", {})
        network = analysis.get("network", {})

        st.markdown(
            f"""
            <div class="info-panel">
                <strong>Application</strong><br>
                <span class="muted">{report.get("app_name", "Unknown")}</span><br><br>
                <strong>Package</strong><br>
                <span class="muted">{report.get("package_name", "Unknown")}</span><br><br>
                <strong>SHA-256</strong><br>
                <span class="muted">{file_data.get("sha256", "Not available")}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with tech_col:
        st.markdown('<div class="section-title">Static Signals</div>', unsafe_allow_html=True)
        s1, s2, s3 = st.columns(3)
        s1.metric("Activities", components.get("activity_count", 0))
        s2.metric("Network APIs", api_usage.get("network", 0))
        s3.metric("URLs", network.get("url_count", 0))

        permissions = analysis.get("permissions", {})
        enabled_permissions = [
            name.replace("has_", "").replace("_", " ").title()
            for name, enabled in permissions.items()
            if enabled
        ]
        st.markdown(
            "Active permissions: "
            + (", ".join(enabled_permissions) if enabled_permissions else "None detected")
        )

    st.markdown('<div class="section-title">Threat Findings</div>', unsafe_allow_html=True)
    if findings:
        for finding in findings:
            st.markdown(
                f"""
                <div class="finding">
                    <strong>{finding.get("severity", "UNKNOWN")} - {finding.get("issue", "Finding")}</strong><br>
                    <span class="muted">{finding.get("reason", "")}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )
    else:
        st.success("No threat findings were reported by the rule engine.")

    st.markdown('<div class="section-title">Behaviour Analysis</div>', unsafe_allow_html=True)
    if behaviours:
        for behaviour in behaviours:
            st.markdown(
                f"""
                <div class="finding">
                    <strong>{behaviour.get("risk", "UNKNOWN")} - {behaviour.get("name", "Behaviour")}</strong><br>
                    <span class="muted">{behaviour.get("description", "")}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )
    else:
        st.info("No correlated behaviour risks were reported.")

    st.markdown('<div class="section-title">AI Security Explanation</div>', unsafe_allow_html=True)
    if ai_text:
        st.markdown(
            f"""
            <div class="info-panel">
                {ai_text}
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.warning("AI explanation is not available yet. Enable AI explanation and scan again.")

else:
    st.markdown('<div class="section-title">No Report Yet</div>', unsafe_allow_html=True)
    st.markdown(
        """
        <div class="info-panel">
            Upload an APK and press <strong>Scan APK</strong> to generate the security report.
        </div>
        """,
        unsafe_allow_html=True,
    )
