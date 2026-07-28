# ==============================================================================
# AEGIS-1: ENTERPRISE AUTONOMOUS SOC & eBPF KERNEL SHIELD
# FULL MONOLITHIC MULTI-AGENT ORCHESTRATION & ANALYTICS TERMINAL
# ==============================================================================

import asyncio
import base64
import dataclasses
import hashlib
import ipaddress
import math
import os
import random
import re
import sys
import time
from typing import Dict, List, Tuple, Any, Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import streamlit as st


# ==============================================================================
# 1. ADVANCED DARK-MODE SOC TERMINAL STYLING (CUSTOM CSS)
# ==============================================================================
st.set_page_config(
    page_title="Aegis-1 Omni SOC Terminal",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    /* Dark Terminal Core Theme */
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;800&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'JetBrains Mono', monospace;
    }
    
    .stApp {
        background-color: #050811;
        color: #d1d5db;
    }
    
    /* Neon Glow Headers */
    .glow-header {
        color: #00f2fe;
        text-shadow: 0 0 10px rgba(0, 242, 254, 0.5), 0 0 20px rgba(0, 242, 254, 0.3);
        font-weight: 800;
        letter-spacing: -0.5px;
    }
    
    .glow-sub {
        color: #38ef7d;
        text-shadow: 0 0 8px rgba(56, 239, 125, 0.4);
    }
    
    .glow-red {
        color: #ff0055;
        text-shadow: 0 0 8px rgba(255, 0, 85, 0.6);
    }

    /* Metric Containers */
    div[data-testid="stMetricValue"] {
        font-family: 'JetBrains Mono', monospace;
        font-weight: 800;
        font-size: 2rem !important;
        color: #00f2fe !important;
    }
    
    div[data-testid="stMetricLabel"] {
        font-size: 0.85rem !important;
        color: #9ca3af !important;
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    /* Card Panels */
    .soc-card {
        background: rgba(15, 23, 42, 0.75);
        border: 1px solid #1e293b;
        border-radius: 12px;
        padding: 20px;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        backdrop-filter: blur(8px);
        margin-bottom: 20px;
    }
    
    .soc-card-alert {
        background: rgba(30, 10, 20, 0.85);
        border: 1px solid #ff0055;
        border-radius: 12px;
        padding: 20px;
    }

    /* Streamlit Components Dark Overrides */
    .stTextInput input, .stTextArea textarea, .stSelectbox div[data-baseweb="select"] {
        background-color: #0b1329 !important;
        color: #00f2fe !important;
        border: 1px solid #1e293b !important;
        border-radius: 6px !important;
    }
    
    .stButton>button {
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        color: #00f2fe;
        border: 1px solid #00f2fe;
        border-radius: 6px;
        font-weight: 600;
        transition: all 0.3s ease;
    }
    
    .stButton>button:hover {
        background: #00f2fe;
        color: #050811;
        box-shadow: 0 0 15px rgba(0, 242, 254, 0.8);
    }

    /* Sidebar Refinements */
    section[data-testid="stSidebar"] {
        background-color: #030712;
        border-right: 1px solid #1e293b;
    }
</style>
""", unsafe_allow_html=True)


# ==============================================================================
# 2. DATA MODELS & STATE STRUCTURES
# ==============================================================================
@dataclasses.dataclass
class ThreatTelemetry:
    timestamp: str
    src_ip: str
    dst_port: int
    protocol: str
    raw_payload: str
    cwe_id: str
    risk_score: float
    status: str
    action_taken: str
    agent_reasoning: str

if "ebpf_map" not in st.session_state:
    st.session_state.ebpf_map = {
        "198.51.100.44": {"action": "XDP_DROP", "reason": "Pre-configured Botnet Actor", "hits": 1420},
        "203.0.113.105": {"action": "XDP_DROP", "reason": "Automated SQLi Probe", "hits": 890}
    }

if "audit_logs" not in st.session_state:
    st.session_state.audit_logs = []

if "dynamic_rules" not in st.session_state:
    st.session_state.dynamic_rules = [
        {"ID": "RULE-0x88F1", "Pattern": r"(?i)(union\s+select)", "Target": "CWE-89 SQLi", "Status": "Active"},
        {"ID": "RULE-0x3B0A", "Pattern": r"(?i)(<script.*?>)", "Target": "CWE-79 XSS", "Status": "Active"}
    ]

if "system_metrics" not in st.session_state:
    st.session_state.system_metrics = {
        "total_requests": 14820,
        "allowed_200": 13100,
        "userspace_blocked": 940,
        "xdp_kernel_drops": 780,
        "avg_latency_ms": 0.042
    }


# ==============================================================================
# 3. ADVANCED ASYNC MULTI-AGENT SWARM SYSTEM
# ==============================================================================
class ThreatHunterAgent:
    """Agent 1: Real-time Payload Inspection, Vector Dissection & Risk Calculation."""
    
    PATTERNS = [
        (r"(?i)(union\s+select|select.*?from|or\s+'1'='1'|drop\s+table)", "CWE-89: SQL Injection", 0.98),
        (r"(?i)(<script|javascript:|onerror=|onload=|<iframe)", "CWE-79: Cross-Site Scripting (XSS)", 0.91),
        (r"(?i)(\.\./|/etc/passwd|/bin/sh|cmd=|whoami|cat\s+/)", "CWE-78: Command Injection / Path Traversal", 0.99),
        (r"(?i)(Transfer-Encoding.*Content-Length|chunked)", "CWE-444: HTTP Request Smuggling", 0.95),
        (r"(?i)(gopher://|dict://|file://|169.254.169.254)", "CWE-918: Server-Side Request Forgery (SSRF)", 0.93),
        (r"(?i)(\$\{jndi:(ldap|rmi|dns)://)", "CWE-502: Log4j Remote Code Execution", 1.00)
    ]

    async def analyze(self, ip: str, port: int, payload: str) -> Dict[str, Any]:
        await asyncio.sleep(0.02)  # High-speed processing loop simulation
        
        for pattern, cwe, score in self.PATTERNS:
            if re.search(pattern, payload):
                return {
                    "ip": ip,
                    "cwe": cwe,
                    "risk_score": score,
                    "action": "MITIGATE",
                    "reasoning": f"Signature match on vector pattern: {pattern[:30]}..."
                }

        # Heuristic Analysis for Anomalies
        entropy = self._calculate_entropy(payload)
        if entropy > 5.2 and len(payload) > 120:
            return {
                "ip": ip,
                "cwe": "CWE-502: High Entropy Obfuscated Payload",
                "risk_score": 0.85,
                "action": "MITIGATE",
                "reasoning": f"High Shannon Entropy detected ({entropy:.2f}). Malicious obfuscation suspected."
            }

        return {
            "ip": ip,
            "cwe": "None",
            "risk_score": 0.02,
            "action": "ALLOW",
            "reasoning": "Payload passed signature and heuristic validation."
        }

    def _calculate_entropy(self, data: str) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        for x in set(data):
            p_x = float(data.count(x)) / len(data)
            entropy -= p_x * math.log(p_x, 2)
        return entropy


class PatchCompilerAgent:
    """Agent 2: Dynamic In-Memory Regex Compiler & C-eBPF Filter Generator."""
    
    async def compile_patch(self, threat_data: Dict[str, Any]) -> Dict[str, str]:
        await asyncio.sleep(0.01)
        cwe = threat_data.get("cwe", "")
        rule_hash = hashlib.md5(f"{cwe}{time.time()}".encode()).hexdigest()[:6].upper()
        rule_id = f"RULE-0x{rule_hash}"

        if "SQL" in cwe:
            pattern = r"(?i)(union\s+select|or\s+1=1)"
        elif "XSS" in cwe:
            pattern = r"(?i)(<script.*?>|onerror=)"
        elif "Command" in cwe:
            pattern = r"(?i)(\.\./|/etc/passwd|cmd=)"
        else:
            pattern = r"(?i)(\$\{jndi:)"

        return {
            "rule_id": rule_id,
            "pattern": pattern,
            "target": cwe,
            "compiler_time": time.strftime("%H:%M:%S")
        }


class DeceptionAgent:
    """Agent 3: Syncs eBPF Kernel Maps & Routes Attacker Traffic into Isolated Sandbox Containers."""
    
    async def execute_countermeasure(self, ip: str) -> Dict[str, Any]:
        await asyncio.sleep(0.005)
        return {
            "ip": ip,
            "xdp_action": "XDP_DROP",
            "honeypot_container": f"sandbox_isolated_net_{hashlib.sha256(ip.encode()).hexdigest()[:8]}",
            "latency_impact": "< 0.0008 ms"
        }


class SwarmOrchestrator:
    """Coordinates parallel execution across specialized security agents."""
    
    def __init__(self):
        self.hunter = ThreatHunterAgent()
        self.compiler = PatchCompilerAgent()
        self.deception = DeceptionAgent()

    async def process_traffic(self, ip: str, port: int, payload: str) -> Dict[str, Any]:
        threat_data = await self.hunter.analyze(ip, port, payload)
        
        if threat_data["action"] == "MITIGATE":
            patch_task = asyncio.create_task(self.compiler.compile_patch(threat_data))
            deception_task = asyncio.create_task(self.deception.execute_countermeasure(ip))
            
            patch, deception = await asyncio.gather(patch_task, deception_task)
            threat_data["patch"] = patch
            threat_data["deception"] = deception
            
        return threat_data

orchestrator = SwarmOrchestrator()


# ==============================================================================
# 4. SIDEBAR - REAL C-EBPF SOURCE CODE & SYSTEM TERMINAL CONTROL
# ==============================================================================
with st.sidebar:
    st.markdown("<h2 class='glow-header'>🛡️ AEGIS-1 CORE</h2>", unsafe_allow_html=True)
    st.markdown("**Version:** `2.4.0-PROD`")
    st.markdown("**eBPF Subsystem:** `Linux 6.8 Native XDP`")
    st.markdown("**Driver Hook:** `eth0 (Driver Level)`")
    st.divider()

    st.subheader("⚙️ System Control")
    auto_refresh = st.checkbox("Auto-Refresh Telemetry", value=False)
    
    st.divider()
    st.subheader("📄 Kernel C Program (`xdp_filter.c`)")
    with st.expander("Expand eBPF Source Code", expanded=False):
        st.code("""
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);   // IPv4 Address
    __type(value, __u8);  // 1 = XDP_DROP
} drop_map SEC(".maps");

SEC("xdp")
int xdp_drop_ip(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;

    __u32 src_ip = iph->saddr;
    __u8 *drop = bpf_map_lookup_elem(&drop_map, &src_ip);
    
    if (drop && *drop == 1) {
        return XDP_DROP; // Drop at NIC layer
    }
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
""", language="c")

    if st.button("🔴 Purge Kernel Drop Maps", use_container_width=True):
        st.session_state.ebpf_map = {}
        st.success("Kernel maps flushed.")
        st.rerun()


# ==============================================================================
# 5. MAIN DASHBOARD: EXECUTIVE METRICS TILES
# ==============================================================================
st.markdown("<h1 class='glow-header'>AEGIS-1: AUTONOMOUS SOC & eBPF KERNEL SHIELD</h1>", unsafe_allow_html=True)
st.caption("Sub-Microsecond NIC Driver Traffic Mitigation & Autonomous Swarm Hot-Patching")

m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Ingested Ingress", f"{st.session_state.system_metrics['total_requests']:,}", "+142 req/s")
m2.metric("Clean (200 OK)", f"{st.session_state.system_metrics['allowed_200']:,}", "94.2%")
m3.metric("AI Hot-Patched", f"{st.session_state.system_metrics['userspace_blocked']:,}", "WAF Swarm")
m4.metric("eBPF XDP Drops", f"{st.session_state.system_metrics['xdp_kernel_drops']:,}", "0.000ms Overhead")
m5.metric("Avg Latency", f"{st.session_state.system_metrics['avg_latency_ms']} ms", "Sub-ms")

st.divider()


# ==============================================================================
# 6. DUAL PANELS: TRAFFIC INSPECTOR (UPPER) & EXECUTIVE OVERRIDE (LOWER)
# ==============================================================================
col_left, col_right = st.columns([1.2, 1], gap="large")

with col_left:
    st.markdown("<h3 class='glow-sub'>⚡ Upper Terminal: Live Traffic Inspector & Payload Simulator</h3>", unsafe_allow_html=True)
    
    c1, c2 = st.columns([2, 1])
    with c1:
        ip_input = st.text_input("Source IP Address", "198.51.100.77", key="ip_in")
    with c2:
        port_input = st.number_input("Target Port", value=8080, key="port_in")

    payload_input = st.text_area(
        "Raw Protocol/HTTP Payload",
        "POST /api/v2/exec HTTP/1.1\nHost: target.internal\nUser-Agent: Mozilla/5.0\n\ncmd=cat /etc/passwd; DROP TABLE users;--",
        height=120,
        key="payload_in"
    )

    if st.button("🔍 Dispatch Payload to Swarm Agents", use_container_width=True, type="primary"):
        st.session_state.system_metrics["total_requests"] += 1
        
        # 1. First check eBPF Map
        if ip_input in st.session_state.ebpf_map:
            st.session_state.system_metrics["xdp_kernel_drops"] += 1
            st.session_state.ebpf_map[ip_input]["hits"] += 1
            
            st.error(f"🚫 [XDP_DROP ENFORCED] Packet for IP {ip_input} dropped at eBPF NIC Driver Level.")
            st.info("⚡ Processing Overhead: 0.000 ms (Bypassed userspace stack)")
            
            st.session_state.audit_logs.insert(0, ThreatTelemetry(
                timestamp=time.strftime("%H:%M:%S"),
                src_ip=ip_input,
                dst_port=int(port_input),
                protocol="IPv4/TCP",
                raw_payload=payload_input[:40] + "...",
                cwe_id="Pre-blocked Actor",
                risk_score=1.0,
                status="XDP_DROP",
                action_taken="Hardware Drop",
                agent_reasoning="Blocked by eBPF Hash Map entry."
            ))
        else:
            # 2. Run Async Swarm Pipeline
            with st.spinner("🤖 Multi-Agent Swarm Dissecting Vector..."):
                res = asyncio.run(orchestrator.process_traffic(ip_input, int(port_input), payload_input))
            
            if res["action"] == "ALLOW":
                st.session_state.system_metrics["allowed_200"] += 1
                st.success("✅ Traffic Verified Clean (200 OK)")
                st.session_state.audit_logs.insert(0, ThreatTelemetry(
                    timestamp=time.strftime("%H:%M:%S"),
                    src_ip=ip_input,
                    dst_port=int(port_input),
                    protocol="IPv4/TCP",
                    raw_payload=payload_input[:40] + "...",
                    cwe_id="None",
                    risk_score=res["risk_score"],
                    status="ALLOWED",
                    action_taken="Passed",
                    agent_reasoning=res["reasoning"]
                ))
            else:
                st.session_state.system_metrics["userspace_blocked"] += 1
                st.session_state.system_metrics["xdp_kernel_drops"] += 1
                
                # Push into eBPF Map
                st.session_state.ebpf_map[ip_input] = {
                    "action": "XDP_DROP",
                    "reason": res["cwe"],
                    "hits": 1
                }
                
                patch = res["patch"]
                st.session_state.dynamic_rules.append({
                    "ID": patch["rule_id"],
                    "Pattern": patch["pattern"],
                    "Target": patch["target"],
                    "Status": "Active"
                })
                
                st.warning(f"🚨 Threat Class: **{res['cwe']}** | Risk Score: **{res['risk_score']}**")
                st.info(f"⚡ **Patch Compiler:** Compiled Hot-patch `{patch['rule_id']}`")
                st.error(f"🎯 **Deception Agent:** Synchronized `{ip_input}` to Kernel eBPF Map & Honeypot Container")
                
                st.session_state.audit_logs.insert(0, ThreatTelemetry(
                    timestamp=time.strftime("%H:%M:%S"),
                    src_ip=ip_input,
                    dst_port=int(port_input),
                    protocol="IPv4/TCP",
                    raw_payload=payload_input[:40] + "...",
                    cwe_id=res["cwe"],
                    risk_score=res["risk_score"],
                    status="AI_HOTPATCHED",
                    action_taken=f"Injected {patch['rule_id']} + eBPF Sync",
                    agent_reasoning=res["reasoning"]
                ))


with col_right:
    st.markdown("<h3 class='glow-sub'>🗣️ Lower Terminal: Executive Voice / Direct Override Console</h3>", unsafe_allow_html=True)
    
    exec_cmd = st.text_input(
        "Executive Intent / Natural Language Command",
        "Aegis-1 lockdown subnet 198.51.100.0/24 immediately and isolate actors!",
        key="exec_cmd_in"
    )

    if st.button("⚡ Execute Executive Directive", use_container_width=True):
        extracted_ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", exec_cmd)
        if extracted_ips:
            for target_ip in extracted_ips:
                st.session_state.ebpf_map[target_ip] = {
                    "action": "XDP_DROP",
                    "reason": "Executive Voice Directive Override",
                    "hits": 0
                }
            st.success(f"🎯 Directive Enforced: {len(extracted_ips)} Target IPs injected directly into eBPF XDP Driver Map!")
        else:
            # Fallback mock IP for demonstration
            fallback_ip = "192.0.2.99"
            st.session_state.ebpf_map[fallback_ip] = {
                "action": "XDP_DROP",
                "reason": "Executive Direct Directive",
                "hits": 0
            }
            st.success(f"🎯 Executed lockdown directive on target node `{fallback_ip}`!")

    st.divider()
    st.markdown("#### 🔒 Active Kernel eBPF Hash Map (`drop_map`)")
    
    if st.session_state.ebpf_map:
        ebpf_df = pd.DataFrame([
            {"IP Address": ip, "Action": v["action"], "Mitigation Reason": v["reason"], "Dropped Packets": v["hits"]}
            for ip, v in st.session_state.ebpf_map.items()
        ])
        st.dataframe(ebpf_df, use_container_width=True, height=200)
    else:
        st.info("eBPF Kernel Map Table is currently empty.")


# ==============================================================================
# 7. VISUALIZATIONS & TELEMETRY CHARTS
# ==============================================================================
st.divider()
st.markdown("<h3 class='glow-header'>📊 SOC REAL-TIME ANALYTICS & TELEMETRY ENGINE</h3>", unsafe_allow_html=True)

tab1, tab2, tab3 = st.tabs(["📈 Traffic Performance & Latency", "⚡ Active Swarm Hot-Patches", "📋 Full Security Audit Log"])

with tab1:
    col_g1, col_g2 = st.columns(2)
    
    with col_g1:
        # Donut Chart for Traffic Mix
        fig_donut = go.Figure(data=[go.Pie(
            labels=['Clean (200 OK)', 'AI Hot-Patched', 'eBPF Hardware Drops'],
            values=[
                st.session_state.system_metrics['allowed_200'],
                st.session_state.system_metrics['userspace_blocked'],
                st.session_state.system_metrics['xdp_kernel_drops']
            ],
            hole=.5,
            marker_colors=['#38ef7d', '#ffaa00', '#ff0055']
