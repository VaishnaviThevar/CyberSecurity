import streamlit as st
import requests

st.set_page_config(page_title="Web Vulnerability & Security Header Auditor", page_icon="🛡️", layout="wide")

st.title("🛡️ Web Vulnerability & Security Header Auditor")
st.write("Analyze target domain HTTP security headers and identify potential security posture risks.")

# Sidebar options
st.sidebar.header("Scan Settings")
demo_mode = st.sidebar.checkbox("Enable Offline / Demo Data Mode", value=False)

target_url = st.text_input("Enter Target URL (e.g., https://google.com or https://example.com)", "https://google.com")

if st.button("🔍 Run Security Scan"):
    headers = None
    status_code = 200
    
    if demo_mode:
        st.info("ℹ️ Running in Offline / Demo Mode using simulated server headers.")
        # Simulated header dataset for demo/offline presentations
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Frame-Options": "SAMEORIGIN",
            "X-Content-Type-Options": "nosniff",
            "Server": "nginx/1.18.0"
        }
    else:
        if not target_url.startswith(("http://", "https://")):
            st.error("Please include http:// or https:// in the URL.")
            st.stop()
            
        with st.spinner("Connecting to target server and checking security posture..."):
            try:
                # Added browser User-Agent so websites don't block python requests
                req_headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
                response = requests.get(target_url, headers=req_headers, timeout=5, allow_redirects=True)
                headers = response.headers
                status_code = response.status_code
            except Exception as e:
                st.error(f"Network Connection Error: Could not resolve target address.")
                st.warning("👉 **Tip for Class Demo:** Turn ON 'Enable Offline / Demo Data Mode' in the left sidebar to run the scan without internet connection!")
                st.stop()

    if headers:
        st.success(f"Successfully audited target server! HTTP Status Code: {status_code}")
        
        st.subheader("1. Critical Security Headers Audit")
        
        security_headers = {
            "Strict-Transport-Security": "Enforces secure HTTPS connections (HSTS).",
            "Content-Security-Policy": "Mitigates Cross-Site Scripting (XSS) and data injection.",
            "X-Frame-Options": "Protects users against Clickjacking attacks.",
            "X-Content-Type-Options": "Prevents MIME-sniffing vulnerabilities.",
            "Referrer-Policy": "Restricts referrer information sent in headers."
        }
        
        passed = 0
        for header_name, description in security_headers.items():
            if header_name in headers:
                st.write(f"✅ **{header_name}**: `PRESENT` — {description}")
                passed += 1
            else:
                st.write(f"❌ **{header_name}**: `MISSING` — {description}")
        
        st.markdown("---")
        st.subheader("2. Security Rating Summary")
        score = int((passed / len(security_headers)) * 100)
        
        col1, col2 = st.columns(2)
        col1.metric("Security Posture Score", f"{score}%")
        
        if score >= 80:
            col2.success("Rating: **STRONG** (High level of header protection)")
        elif score >= 50:
            col2.warning("Rating: **MODERATE** (Missing essential defense headers)")
        else:
            col2.error("Rating: **VULNERABLE** (Missing critical security headers)")

        st.subheader("3. Received HTTP Headers Log")
        st.json(dict(headers))