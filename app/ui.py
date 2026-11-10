import streamlit as st
import httpx
import os

# --- CONFIG ---
# Use the internal Docker network name to talk to the API container
API_URL = os.getenv("API_URL", "http://api:8000")

st.set_page_config(
    page_title="Aegis-Sentinel SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- STATE MANAGEMENT ---
if "messages" not in st.session_state:
    st.session_state.messages = []
if "token" not in st.session_state:
    st.session_state.token = None

# --- SIDEBAR: AUTH & SETTINGS ---
with st.sidebar:
    st.title("🛡️ Aegis-Sentinel")
    st.caption("Enterprise AI Threat Intelligence")
    
    st.divider()
    
    if not st.session_state.token:
        st.subheader("🔐 Authentication")
        username = st.text_input("Username", value="admin")
        password = st.text_input("Password", type="password", value="password123")
        
        if st.button("Login", use_container_width=True):
            try:
                response = httpx.post(
                    f"{API_URL}/api/token", 
                    data={"username": username, "password": password},
                    timeout=10
                )
                if response.status_code == 200:
                    st.session_state.token = response.json()["access_token"]
                    st.success("Authenticated!")
                    st.rerun()
                else:
                    st.error("Invalid credentials")
            except Exception as e:
                st.error(f"Connection error: {e}")
    else:
        st.success("✅ Authenticated as Admin")
        if st.button("Logout", use_container_width=True):
            st.session_state.token = None
            st.session_state.messages = []
            st.rerun()
    
    st.divider()
    
    st.subheader("⚙️ Workflow Settings")
    use_agent = st.toggle(
        "Enable Multi-Agent (MCP)", 
        value=True, 
        help="Turn OFF for standard RAG (faster). Turn ON for LangGraph orchestration (Triage + Remediation)."
    )
    
    source_filter = st.selectbox(
        "Source Filter", 
        [None, "cisa", "nvd", "hackernews", "bleepingcomputer", "owasp", "cisco_talos", "krebsonsecurity", "unit42"],
        format_func=lambda x: "All Sources" if x is None else x
    )
    
    days_back = st.number_input(
        "Temporal Filter (Days)", 
        min_value=0, 
        value=0, 
        step=1,
        help="0 = All Time. 7 = Last 7 days."
    )

# --- MAIN CHAT INTERFACE ---
st.title("Threat Intelligence Analyst")
st.caption("Ask about CVEs, VDBs, vulnerabilities, or request remediation plans.")

# Display chat history
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Chat Input
if prompt := st.chat_input("E.g., How do I fix VDB-249838?", disabled=not st.session_state.token):
    # 1. Add user message to history
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # 2. Call the API
    with st.chat_message("assistant"):
        with st.spinner("Analyzing threat intel..."):
            headers = {"Authorization": f"Bearer {st.session_state.token}"}
            
            endpoint = "/api/agent" if use_agent else "/api/ask"
            payload = {
                "question": prompt,
                "source_filter": source_filter if source_filter else None,
                "days_back": days_back if days_back > 0 else None
            }
            
            try:
                response = httpx.post(
                    f"{API_URL}{endpoint}", 
                    json=payload, 
                    headers=headers, 
                    timeout=120
                )
                response.raise_for_status()
                data = response.json()
                
                # 3. Render the response beautifully
                if use_agent:
                    # --- Multi-Agent Response ---
                    st.markdown("#### 🧠 Triage Decision")
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Needs Search", "✅ Yes" if data['triage_decision']['needs_search'] else "❌ No")
                    with col2:
                        st.metric("Needs Remediation", "✅ Yes" if data['triage_decision']['needs_remediation'] else "❌ No")
                    
                    st.markdown("#### 📊 Threat Intel Retrieved")
                    st.info(data.get("context_snippet", "No context found."))
                    
                    if data.get("remediation_plan") and data["remediation_plan"] != "No remediation requested.":
                        st.markdown("#### 🛠️ Remediation Plan")
                        st.success(data["remediation_plan"])
                    
                    final_answer = data.get("ai_answer", "")
                
                else:
                    # --- Standard RAG Response ---
                    st.markdown("#### 📊 Retrieved Context")
                    st.info(data.get("context_snippet", "No context found."))
                    final_answer = data.get("ai_answer", "")
                
                st.markdown("#### 💡 Final Answer")
                st.markdown(final_answer)
                
                # Add to history
                st.session_state.messages.append({"role": "assistant", "content": final_answer})
                
            except Exception as e:
                st.error(f"Error: {e}")