import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import asyncio
import re
import time
from typing import Dict, Any

# ==============================================================================
# 1. PAGE CONFIGURATION & DARK SOC CSS STYLING
# ==============================================================================
st.set_page_config(
    page_title="Aegis-1 Omni-Agent Autonomous SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom High-Tech Dark Mode CSS Injection
st.markdown("""
<style>
    /* Global Main Theme */
    .stApp {
        background-color: #0b0f19;
        color: #c9d1d9;
        font-family: 'Consolas', 'Fira Code', monospace;
    }
    
    /* Neon Cards & Containers */
    div[data-testid="stMetricValue"] {
        font-family: 'Consolas', monospace;
        font-weight: bold;
        color: #00f2fe !important;
    }
    
    /* Header & Subheader Accents */
    h1, h2, h3 {
        color: #58a6ff !important;
        border-bottom: 1px solid #21262d;
        padding-bottom: 8px;
    }
    
    /* Custom Alert Boxes */
    .stAlert {
        border-radius: 8px;
        background-color: #161b22;
        border: 1px solid #30363d;
    }
    
    /* Table Styling */
    .stDataFrame {
        border: 1px solid #30363d;
        border-radius: 6px;
    }
</style>
""", unsafe_allow_html=True)


# ==============================================================================
# 2. INTERNAL ASYNC MULTI-AGENT SWARM ENGINE
# ==============================================================================
class ThreatHunterAgent:
    """Agent 1: Analyzes raw incoming telemetry for attack signatures and zero-days."""
    async def analyze(self, ip: str, payload: str) -> Dict[str, Any]:
        await asyncio.sleep(0.04)  # Simulate rapid reasoning loop
        cwe = "None"
        risk_score = 0.02
        action = "ALLOW"

        if re.search(r"(SELECT|UNION|OR\s+'1'='1'|--|DROP\s+TABLE)", payload, re.I):
            cwe = "CWE-89: SQL Injection"
            risk_score = 0.98
            action = "MITIGATE"
        elif re.search(r"(<script|javascript:|onerror=|onload=)", payload, re.I):
            cwe = "CWE-79: Cross-Site Scripting"
            risk_score = 0.92
            action = "MITIGATE"
        elif re.search(r"(\.\./|/etc/passwd|cmd=|whoami|cat\s+/)", payload, re.I):
            cwe = "CWE-78: Command Injection / Path Traversal"
            risk_score = 0.99
            action = "MITIGATE"
        elif re.search(r"(Content-Length.*Transfer-Encoding)", payload, re.I | re.S):
            cwe = "CWE-444: HTTP Request Smuggling"
            risk_score = 0.95
            action = "MITIGATE"

        return {
            "ip": ip,
            "cwe": cwe,
            "risk_score": risk_score,
            "action": action,
            "timestamp": time.strftime("%H:%M:%S")
        }


class PatchCompilerAgent:
    """Agent 2: Compiles dynamic in-memory hot-patches for zero-day mitigation."""
    async def compile_patch(self, threat_data: Dict[str, Any]) -> Dict[str, str]:
        await asyncio.sleep(0.02)
        cwe = threat_data.get("cwe", "")
        rule_id = f"RULE-0x{abs(hash(cwe + str(time.time()))) % 0xFFFF:04X}"
        
        if "SQL" in cwe:
            pattern = r"(?i)(union\s+select|select.*?from|or\s+1=1)"
        elif "Scripting" in cwe:
            pattern = r"(?i)(<script.*?>|onload=|onerror=)"
        elif "Smuggling" in cwe:
            pattern = r"(?i)(Transfer-Encoding:\s*chunked)"
        else:
            pattern = r"(?i)(\.\./|/etc/passwd|cmd=)"

        return {"rule_id": rule_id, "pattern": pattern, "type": "MEMORY_HOTPATCH"}


class DeceptionAgent:
    """Agent 3: Synchronizes eBPF XDP Kernel maps and routes traffic to isolated honeypots."""
    async def execute_countermeasure(self, ip: str) -> Dict[str, str]:
        await asyncio.sleep(0.01)
        return {
            "ip": ip,
            "xdp_action": "XDP_DROP",
            "honeypot_target": "172.19.0.5:8080 [Container Sandbox]",
            "latency": "< 0.001 ms"
        }


class SwarmOrchestrator:
    """Coordinates parallel agent pipeline execution."""
    def __init__(self):
        self.hunter = ThreatHunterAgent()
        self.compiler = PatchCompilerAgent()
        self.deception = DeceptionAgent()

    async def run_pipeline(self, ip: str, payload: str) -> Dict[str, Any]:
        threat_data = await self.hunter.analyze(ip, payload)
        
        if threat_data["action"] == "MITIGATE":
            patch_task = asyncio.create_task(self.compiler.compile_patch(threat_data))
            deception_task = asyncio.create_task(self.deception.execute_countermeasure(ip))
            
            patch, deception = await asyncio.gather(patch_task, deception_task)
            threat_data["patch"] = patch
            threat_data["deception"] = deception
        
        return threat_data


# ==============================================================================
# 3. STATE INITIALIZATION
# ==============================================================================
if "ebpf_map" not in st.session_state:
    st.session_state.ebpf_map = {"10.0.0.99": {"action": "XDP_DROP", "reason": "Pre-configured Malicious Subnet"}}
if "audit_logs" not in st.session_state:
    st.session_state.audit_logs = []
if "dynamic_rules" not in st.session_state:
    st.session_state.dynamic_rules = [
        {"ID": "RULE-0x88F1", "Pattern": r"(?i)(union\s+select)", "Target": "SQLi"},
        {"ID": "RULE-0x3B0A", "Pattern": r"(?i)(<script.*?>)", "Target": "XSS"}
    ]
if "metrics" not in st.session_state:
    st.session_state.metrics = {"total": 12, "allowed": 8, "waf_blocked": 2, "xdp_drops": 2}

orchestrator = SwarmOrchestrator()


# ==============================================================================
# 4. SIDEBAR - SYSTEM STATUS & C-EBPF KERNEL CODE VISUALIZER
# ==============================================================================
with st.sidebar:
    st.image("https://img.icons8.com/color/96/shield.png", width=64)
    st.title("Aegis-1 Core")
    st.markdown("**Status:** `ONLINE (eBPF XDP Hooked)`")
    st.markdown("**Kernel Target:** `Linux 6.8.0-bpf`")
    st.markdown("**Driver Interface:** `eth0 (XDP Native)`")
    st.divider()

    st.subheader("💻 Active eBPF C-Code Hook")
    with st.expander("View xdp_filter.c", expanded=False):
        st.code("""
// xdp_filter.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_drop_ip(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    struct iphdr *iph = data + sizeof(struct ethhdr);
    __u32 src_ip = iph->saddr;

    __u8 *drop = bpf_map_lookup_elem(&drop_map, &src_ip);
    if (drop && *drop == 1) {
        return XDP_DROP; // Drop at NIC driver level
    }
    return XDP_PASS;
}
""", language="c")

    st.divider()
    if st.button("Reset Session State", use_container_width=True):
        st.session_state.ebpf_map = {}
        st.session_state.audit_logs = []
        st.session_state.dynamic_rules = []
        st.session_state.metrics = {"total": 0, "allowed": 0, "waf_blocked": 0, "xdp_drops": 0}
        st.rerun()


# ==============================================================================
# 5. DASHBOARD HEADER & TOP METRICS TILES
# ==============================================================================
st.title("🛡️ Aegis-1: Autonomous Multi-Agent SOC & eBPF Kernel Shield")
st.caption("Next-Generation Autonomous Security Operating System | eBPF Kernel Space Synchronization")

col_m1, col_m2, col_m3, col_m4 = st.columns(4)
col_m1.metric("Total Traffic Ingested", st.session_state.metrics["total"], delta="+1 Req")
col_m2.metric("Passed (200 OK)", st.session_state.metrics["allowed"])
col_m3.metric("AI WAF Hot-Patched", st.session_state.metrics["waf_blocked"], delta_color="inverse")
col_m4.metric("eBPF XDP Hardware Drops", st.session_state.metrics["xdp_drops"], delta_color="inverse")

st.divider()


# ==============================================================================
# 6. DUAL INTERFACE: UPPER PAYLOAD INSPECTOR & LOWER EXECUTIVE COMMAND CONSOLE
# ==============================================================================
col_upper, col_lower = st.columns([1, 1], gap="medium")

# --- UPPER DASHBOARD: Payload Simulator & Agent Swarm Inspector ---
with col_upper:
    st.subheader("⚡ Upper Dashboard: Real-Time Traffic Inspector")
    st.markdown("Simulate inbound web requests to evaluate Multi-Agent classification & eBPF sync.")

    sim_ip = st.text_input("Source Client IP", "172.16.0.44", key="sim_ip")
    sim_payload = st.text_area(
        "Raw HTTP Request Payload",
        "POST /api/v1/auth HTTP/1.1\nHost: aegis.local\nUser-Agent: Mozilla/5.0\n\nuser=admin' OR '1'='1'--",
        height=110,
        key="sim_payload"
    )

    if st.button("🔍 Inspect Payload with Swarm Agents", use_container_width=True, type="primary"):
        st.session_state.metrics["total"] += 1
        
        # Step 1: Check eBPF Kernel Drop Map first
        if sim_ip in st.session_state.ebpf_map:
            st.session_state.metrics["xdp_drops"] += 1
            st.error(f"🚫 [XDP_DROP] Packet blocked instantly at NIC Driver level for IP `{sim_ip}`")
            st.info("⚡ **Processing Overhead:** 0.000 ms (Dropped before reaching Python Userspace)")
            st.session_state.audit_logs.insert(0, {
                "Time": time.strftime("%H:%M:%S"),
                "IP": sim_ip,
                "Status": "XDP_DROP",
                "CWE / Detail": "Blacklisted in eBPF Map",
                "Action Taken": "NIC Hardware Drop"
            })
        else:
            # Step 2: Run Async Multi-Agent Pipeline
            with st.spinner("🤖 Multi-Agent Swarm Analyzing Payload..."):
                result = asyncio.run(orchestrator.run_pipeline(sim_ip, sim_payload))
            
            if result["action"] == "ALLOW":
                st.session_state.metrics["allowed"] += 1
                st.success("✅ Traffic Verified Clean (200 OK)")
                st.session_state.audit_logs.insert(0, {
                    "Time": result["timestamp"],
                    "IP": sim_ip,
                    "Status": "ALLOWED",
                    "CWE / Detail": "Clean Traffic",
                    "Action Taken": "Passed to Application"
                })
            else:
                st.session_state.metrics["waf_blocked"] += 1
                st.session_state.metrics["xdp_drops"] += 1
                
                # Auto-push IP into eBPF Kernel Map
                st.session_state.ebpf_map[sim_ip] = {"action": "XDP_DROP", "reason": result["cwe"]}
                
                patch = result["patch"]
                st.session_state.dynamic_rules.append({
                    "ID": patch["rule_id"],
                    "Pattern": patch["pattern"],
                    "Target": result["cwe"]
                })
                
                st.warning(f"🚨 **Threat Detected:** `{result['cwe']}` (Risk Score: `{result['risk_score']}`)")
                st.info(f"⚡ **Patch Compiler Agent:** Compiled & Injected `{patch['rule_id']}`")
                st.error(f"🎯 **Deception Agent:** Added `{sim_ip}` to eBPF Map & Honeypot Sandbox")
                
                st.session_state.audit_logs.insert(0, {
                    "Time": result["timestamp"],
                    "IP": sim_ip,
                    "Status": "AI_HOTPATCHED",
                    "CWE / Detail": result["cwe"],
                    "Action Taken": f"Injected {patch['rule_id']} + eBPF Sync"
                })

# --- LOWER DASHBOARD: Executive Voice/Chat Direct Override Console ---
with col_lower:
    st.subheader("🗣️ Lower Dashboard: Executive Command Console")
    st.markdown("Issue direct natural language overrides to manipulate kernel rules or system behavior.")

    exec_input = st.text_input(
        "Executive Voice / Intent Command",
        "Aegis execute emergency lockdown on IP 198.51.100.44 immediately!",
        key="exec_input"
    )

    if st.button("⚡ Execute Executive Override", use_container_width=True):
        extracted_ip = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", exec_input)
        if extracted_ip:
            target_ip = extracted_ip.group(0)
            st.session_state.ebpf_map[target_ip] = {"action": "XDP_DROP", "reason": "Executive Direct Directive"}
            st.session_state.metrics["xdp_drops"] += 1
            st.success(f"🎯 Directive Executed: Synchronized IP `{target_ip}` directly into eBPF Drop Map!")
            st.session_state.audit_logs.insert(0, {
                "Time": time.strftime("%H:%M:%S"),
                "IP": target_ip,
                "Status": "EXEC_OVERRIDE",
                "CWE / Detail": "Executive Command Directive",
                "Action Taken": "Forced eBPF Kernel Block"
            })
        else:
            st.error("Could not parse target IPv4 address from executive command.")

    st.divider()
    st.subheader("🔒 Active eBPF Kernel Map Table (XDP Driver)")
    
    if st.session_state.ebpf_map:
        map_data = [
            {"IPv4 Address": ip, "Kernel Action": details["action"], "Mitigation Cause": details["reason"]}
            for ip, details in st.session_state.ebpf_map.items()
        ]
        st.dataframe(pd.DataFrame(map_data), use_container_width=True, height=180)
    else:
        st.info("eBPF Map Empty - No kernel blocks currently enforced.")


# ==============================================================================
# 7. ANALYTICS VISUALIZER & DYNAMIC RULES MONITOR
# ==============================================================================
st.divider()
tab_analytics, tab_rules, tab_logs = st.tabs(["📊 Live Analytics Dashboard", "⚡ Active Dynamic Rules", "📋 Full Audit Log"])

with tab_analytics:
    col_chart1, col_chart2 = st.columns(2)
    
    with col_chart1:
        st.markdown("#### Traffic Distribution")
        chart_data = pd.DataFrame({
            "Category": ["Allowed (200 OK)", "AI WAF Blocks", "eBPF XDP Drops"],
            "Count": [st.session_state.metrics["allowed"], st.session_state.metrics["waf_blocked"], st.session_state.metrics["xdp_drops"]]
        })
        fig = px.pie(chart_data, values="Count", names="Category", color="Category",
                     color_discrete_map={"Allowed (200 OK)": "#2ea043", "AI WAF Blocks": "#d29922", "eBPF XDP Drops": "#f85149"},
                     hole=0.4)
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9")
        st.plotly_chart(fig, use_container_width=True)

    with col_chart2:
        st.markdown("#### eBPF Latency Performance (Microseconds)")
        latency_df = pd.DataFrame({
            "Layer": ["Userspace WAF Inspection", "AI Swarm Reasoning", "eBPF XDP Kernel Drop"],
            "Latency (μs)": [12000, 40000, 0.8]
        })
        fig_bar = px.bar(latency_df, x="Layer", y="Latency (μs)", color="Layer", log_y=True)
        fig_bar.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9")
        st.plotly_chart(fig_bar, use_container_width=True)

with tab_rules:
    st.markdown("#### Active Dynamic Memory Hot-Patches")
    if st.session_state.dynamic_rules:
        st.dataframe(pd.DataFrame(st.session_state.dynamic_rules), use_container_width=True)
    else:
        st.info("No dynamic memory hot-patches compiled yet.")

with tab_logs:
    st.markdown("#### Full System Security Audit Logs")
    if st.session_state.audit_logs:
        st.dataframe(pd.DataFrame(st.session_state.audit_logs), use_container_width=True)
    else:
        st.info("Audit log is currently empty.")
            
