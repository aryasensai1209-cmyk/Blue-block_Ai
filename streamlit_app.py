import re
import time
import asyncio
import pandas as pd
import streamlit as st

# Set Streamlit Page Configuration
st.set_page_config(
    page_title="Aegis-1 | AI & eBPF Security Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =====================================================================
# 1. KERNEL eBPF / XDP HARDWARE FILTER (SIMULATOR)
# =====================================================================
class KernelXdpFilter:
    def __init__(self):
        self.bpf_ip_blacklist = {}
        self.total_xdp_drops = 0

    def sync_bpf_map_add(self, ip_address: str):
        if ip_address not in self.bpf_ip_blacklist:
            self.bpf_ip_blacklist[ip_address] = 0

    def xdp_driver_hook(self, ip_address: str) -> bool:
        if ip_address in self.bpf_ip_blacklist:
            self.bpf_ip_blacklist[ip_address] += 1
            self.total_xdp_drops += 1
            return True
        return False


class AiWafEngine:
    def __init__(self, kernel: KernelXdpFilter):
        self.kernel = kernel
        self.active_hotpatches = []
        self.stats = {"total": 0, "allowed": 0, "waf_blocked": 0, "kernel_dropped": 0}

    def evaluate_hotpatches(self, payload: str) -> bool:
        for patch in self.active_hotpatches:
            if re.search(patch["pattern"], payload, re.IGNORECASE):
                return True
        return False

    def ai_reasoning_agent(self, payload: str):
        if "SELECT" in payload and ("OR" in payload or "UNION" in payload):
            return {"detected": True, "type": "SQL Injection", "pattern": r"(SELECT|UNION).*?(OR|'1'='1')", "tag": "CWE-89"}
        elif "<script>" in payload or "javascript:" in payload:
            return {"detected": True, "type": "Cross-Site Scripting (XSS)", "pattern": r"(<script.*?>|javascript:)", "tag": "CWE-79"}
        elif "../" in payload or "/etc/passwd" in payload:
            return {"detected": True, "type": "Path Traversal", "pattern": r"(\.\./|/etc/passwd)", "tag": "CWE-22"}
        return {"detected": False}

    def process_incoming_request(self, ip: str, payload: str):
        self.stats["total"] += 1
        if self.kernel.xdp_driver_hook(ip):
            self.stats["kernel_dropped"] += 1
            return "XDP_DROP", f"Dropped at NIC Kernel Level (eBPF Blacklisted IP: {ip})"
        if self.evaluate_hotpatches(payload):
            self.stats["waf_blocked"] += 1
            self.kernel.sync_bpf_map_add(ip)
            return "WAF_BLOCK", "Blocked by Active Hot-Patch (Escalated IP to eBPF Map)"
        threat = self.ai_reasoning_agent(payload)
        if threat["detected"]:
            self.stats["waf_blocked"] += 1
            self.active_hotpatches.append({"type": threat["type"], "pattern": threat["pattern"]})
            self.kernel.sync_bpf_map_add(ip)
            return "AI_HOTPATCHED", f"Zero-Day Neutralized ({threat['type']}). Hot-Patch Compiled & IP Blacklisted."
        self.stats["allowed"] += 1
        return "ALLOWED", "Request Clean (200 OK)"


if "kernel" not in st.session_state:
    st.session_state.kernel = KernelXdpFilter()
if "waf" not in st.session_state:
    st.session_state.waf = AiWafEngine(st.session_state.kernel)
if "logs" not in st.session_state:
    st.session_state.logs = []

kernel = st.session_state.kernel
waf = st.session_state.waf

st.title("🛡️ AEGIS-1: AI & eBPF Kernel Defense Console")
st.caption("Real-Time Cyber Threat Inspection, Autonomous Hot-Patching, and eBPF XDP Hardware Packet Filtering")

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Traffic", waf.stats["total"])
col2.metric("Passed (200 OK)", waf.stats["allowed"])
col3.metric("WAF Blocks", waf.stats["waf_blocked"])
col4.metric("eBPF NIC Drops (XDP)", kernel.total_xdp_drops)

st.divider()

left_col, right_col = st.columns([1, 1])

with left_col:
    st.subheader("⚡ Traffic & Command Simulator")
    with st.form("traffic_form"):
        client_ip = st.text_input("Client IP Address", value="10.0.0.99")
        raw_payload = st.text_area("HTTP Payload Stream", value="GET /login?user=admin' OR '1'='1")
        submit_btn = st.form_submit_button("Send HTTP Request")
    if submit_btn:
        action, details = waf.process_incoming_request(client_ip, raw_payload)
        st.session_state.logs.append({
            "Time": time.strftime("%H:%M:%S"),
            "Client IP": client_ip,
            "Action": action,
            "Details": details,
            "Payload": raw_payload[:40] + "..."
        })
        st.rerun()
    st.subheader("🗣️ Omni Voice/Chat Command")
    command_input = st.text_input("Enter direct instruction (e.g., 'Lockdown IP 192.168.1.50')", "")
    if st.button("Execute Command"):
        if "lockdown" in command_input.lower() or "block" in command_input.lower():
            ips = re.findall(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', command_input)
            for ip in ips:
                kernel.sync_bpf_map_add(ip)
                st.success(f"Pushed IP {ip} to eBPF Kernel Map!")
            st.rerun()

with right_col:
    st.subheader("🧠 Active Dynamic Hot-Patches (Memory)")
    if not waf.active_hotpatches:
        st.info("No active dynamic rules compiled yet.")
    else:
        st.dataframe(pd.DataFrame(waf.active_hotpatches), use_container_width=True)
    st.subheader("⚡ eBPF Kernel BPF Map (Hardware Drop List)")
    if not kernel.bpf_ip_blacklist:
        st.info("Kernel BPF Map is currently empty.")
    else:
        bpf_data = [{"Blacklisted IP": ip, "Packets Dropped at NIC": drops} for ip, drops in kernel.bpf_ip_blacklist.items()]
        st.dataframe(pd.DataFrame(bpf_data), use_container_width=True)

st.divider()
st.subheader("📋 Traffic Inspection Log")
if st.session_state.logs:
    st.dataframe(pd.DataFrame(st.session_state.logs).iloc[::-1], use_container_width=True
