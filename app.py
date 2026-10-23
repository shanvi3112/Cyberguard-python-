import streamlit as st
from pathlib import Path
from datetime import datetime
import hashlib
import json
import re
import socket
import pandas as pd

from utils.passwords import analyze_password
from utils.integrity import sha256_file, load_baseline, save_baseline
from utils.logs import analyze_logs

APP_DIR = Path(__file__).parent
DATA_DIR = APP_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
BASELINE_PATH = DATA_DIR / "integrity_baseline.json"

st.set_page_config(page_title="CyberGuard", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
.main {background: #0b1220;}
.block-container {padding-top: 1.6rem;}
div[data-testid="stMetric"] {background: #111c2e; padding: 14px; border-radius: 12px;}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ CyberGuard")
st.caption("A local, defensive cybersecurity toolkit built with Python")
st.info("Use this toolkit only on files, logs, and devices you own or are explicitly authorized to assess.")

page = st.sidebar.radio("Toolkit", [
    "Overview", "Password Analyzer", "File Integrity", "Security Log Analyzer", "Authorized Port Check"
])

if page == "Overview":
    st.subheader("Security workspace")
    a, b, c = st.columns(3)
    a.metric("Tools", "4")
    b.metric("Storage", "Local JSON")
    c.metric("Mode", "Defensive")
    st.markdown("""
    ### What you can do
    - Assess password hygiene without sending passwords to a server.
    - Create a SHA-256 baseline for files and detect later changes.
    - Inspect authentication logs for repeated failed login attempts.
    - Check a small, chosen list of TCP ports on a device you are authorized to test.

    ### Suggested demo
    1. Test a weak and a stronger sample password.
    2. Create a baseline for a test file, edit it, then verify it again.
    3. Upload the sample log in `sample_data/auth.log`.
    4. Run a port check against `127.0.0.1` on a few common ports.
    """)
    st.warning("This is an educational project, not a replacement for endpoint protection, a SIEM, or a professional security audit.")

elif page == "Password Analyzer":
    st.subheader("Password strength and hygiene")
    st.caption("The password is analyzed locally in this app and is not stored.")
    password = st.text_input("Enter a test password", type="password")
    if st.button("Analyze password", type="primary"):
        if not password:
            st.warning("Enter a password to analyze.")
        else:
            result = analyze_password(password)
            st.metric("Estimated strength", result["label"], f'{result["score"]}/100')
            st.progress(result["score"] / 100)
            st.write("**Checks**")
            for item, passed in result["checks"].items():
                st.write(f'{"✅" if passed else "❌"} {item}')
            if result["tips"]:
                st.write("**Suggestions**")
                for tip in result["tips"]:
                    st.write(f"- {tip}")
            st.caption("This is a simple heuristic, not a guarantee against cracking. Avoid entering a real password into demonstration tools.")

elif page == "File Integrity":
    st.subheader("File integrity monitor")
    st.write("Create a SHA-256 baseline for a file, then verify it later to detect changes.")
    uploaded = st.file_uploader("Choose a file to check", key="integrity_upload")
    if uploaded:
        temp_path = DATA_DIR / "uploaded_check.tmp"
        temp_path.write_bytes(uploaded.getvalue())
        digest = sha256_file(temp_path)
        st.code(digest, language=None)
        st.caption(f"File: {uploaded.name} · Size: {len(uploaded.getvalue())} bytes")
        baseline = load_baseline(BASELINE_PATH)
        current = baseline.get(uploaded.name)
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Save as baseline"):
                baseline[uploaded.name] = {"sha256": digest, "updated_at": datetime.now().isoformat(timespec="seconds")}
                save_baseline(BASELINE_PATH, baseline)
                st.success("Baseline saved locally.")
        with col2:
            if st.button("Compare with baseline"):
                if not current:
                    st.warning("No baseline exists for this filename. Save a baseline first.")
                elif current["sha256"] == digest:
                    st.success("No change detected: SHA-256 matches the saved baseline.")
                else:
                    st.error("Change detected: SHA-256 differs from the saved baseline.")
        if current:
            st.write("Saved baseline:", current["sha256"])
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass
    st.caption("A filename is used as the baseline key. Use unique filenames and keep baseline data protected.")

elif page == "Security Log Analyzer":
    st.subheader("Authentication log analyzer")
    st.write("Upload a text log containing authentication events. The tool flags repeated failed-login patterns.")
    uploaded_log = st.file_uploader("Upload a .log or .txt file", type=["log", "txt"])
    pasted = st.text_area("Or paste sample log lines", height=180, placeholder="Failed password for invalid user test from 192.0.2.10 port 43210 ssh2")
    threshold = st.slider("Flag after this many failed attempts from one IP", min_value=2, max_value=20, value=5)
    if st.button("Analyze logs", type="primary"):
        content = ""
        if uploaded_log:
            content = uploaded_log.getvalue().decode("utf-8", errors="replace")
        elif pasted.strip():
            content = pasted
        else:
            st.warning("Upload a log file or paste log lines.")
        if content:
            summary = analyze_logs(content, threshold)
            x, y, z = st.columns(3)
            x.metric("Lines analyzed", summary["line_count"])
            y.metric("Failed-login events", summary["failed_events"])
            z.metric("IPs flagged", len(summary["flagged_ips"]))
            if summary["flagged_ips"]:
                st.error("Repeated failed-login activity detected.")
                st.dataframe(pd.DataFrame([{"IP address": ip, "Failed attempts": count} for ip, count in summary["flagged_ips"].items()]), use_container_width=True)
            else:
                st.success("No IP exceeded the selected threshold.")
            with st.expander("View parsed event counts"):
                st.json(summary["event_counts"])

elif page == "Authorized Port Check":
    st.subheader("Authorized TCP port check")
    st.warning("Only scan a device you own or have explicit permission to test. Keep the port list small.")
    host = st.text_input("Hostname or IP address", value="127.0.0.1")
    port_text = st.text_input("Ports (comma-separated, max 20)", value="22,80,443,8080")
    timeout = st.slider("Connection timeout (seconds)", 0.2, 2.0, 0.5, 0.1)
    if st.button("Check selected ports", type="primary"):
        try:
            ports = [int(p.strip()) for p in port_text.split(",") if p.strip()]
            if not host.strip():
                raise ValueError("Enter a hostname or IP address.")
            if not ports or len(ports) > 20:
                raise ValueError("Provide between 1 and 20 ports.")
            if any(p < 1 or p > 65535 for p in ports):
                raise ValueError("Ports must be between 1 and 65535.")
            try:
                resolved = socket.getaddrinfo(host.strip(), None, type=socket.SOCK_STREAM)[0][4][0]
            except socket.gaierror:
                raise ValueError("Hostname could not be resolved.")
            results = []
            for port in ports:
                sock = socket.socket(socket.AF_INET6 if ":" in resolved else socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                try:
                    status = "Open" if sock.connect_ex((resolved, port)) == 0 else "Closed or filtered"
                except OSError:
                    status = "Could not determine"
                finally:
                    sock.close()
                results.append({"Host": host.strip(), "Resolved address": resolved, "Port": port, "Result": status})
            st.dataframe(pd.DataFrame(results), use_container_width=True)
            st.caption("A closed/filtered result is not definitive; firewalls and network conditions can affect results.")
        except ValueError as exc:
            st.error(str(exc))

st.sidebar.divider()
st.sidebar.caption("CyberGuard · Educational project")
