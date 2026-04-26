import threading
import datetime
import re
import socket
import os
import subprocess
import struct
import time
import secrets
import hashlib
from functools import wraps
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from scapy.all import sniff, IP, IPv6, TCP, UDP, DNS, DNSQR, DNSRR, ICMP, ARP, Raw, Ether, conf
from flask import Flask, jsonify, request, abort
from flask_cors import CORS

import logging

app = Flask(__name__)

# DNS Thread Pool
dns_executor = ThreadPoolExecutor(max_workers=10)
dns_pending = set()

# ──────────────────────────────────────────────
# SECURITY: Strict CORS — only allow local Electron/Vite frontend
# ──────────────────────────────────────────────
CORS(app, origins=[
    "http://localhost:5173",    # Vite dev server
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "app://.",                  # Electron file protocol
])

# Silence Flask dev server logs
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# ──────────────────────────────────────────────
# SECURITY: API Auth Token (generated on startup)
# ──────────────────────────────────────────────
API_TOKEN = secrets.token_hex(32)
TOKEN_FILE = os.path.join(os.path.dirname(__file__), ".api_token")

def write_token():
    """Write API token to file so the Electron frontend can read it."""
    with open(TOKEN_FILE, "w") as f:
        f.write(API_TOKEN)
    try:
        os.chmod(TOKEN_FILE, 0o644)  # Allow reading by non-root users
    except:
        pass
    print(f"🔐 API token written to {TOKEN_FILE}")

def require_auth(f):
    """Decorator: require valid API token in header or query param."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = (
            request.headers.get("X-API-Token")
            or request.args.get("token")
        )
        if token != API_TOKEN:
            abort(401, description="Unauthorized: invalid or missing API token")
        return f(*args, **kwargs)
    return decorated

# ──────────────────────────────────────────────
# SECURITY: Rate limiting (simple in-memory)
# ──────────────────────────────────────────────
rate_limit_store = defaultdict(list)  # IP -> [timestamps]
RATE_LIMIT = 1000      # max requests
RATE_WINDOW = 60       # per N seconds

def check_rate_limit():
    """Returns True if request is within rate limit."""
    ip = request.remote_addr or "unknown"
    now = time.time()
    # Clean old entries
    rate_limit_store[ip] = [t for t in rate_limit_store[ip] if now - t < RATE_WINDOW]
    if len(rate_limit_store[ip]) >= RATE_LIMIT:
        return False
    rate_limit_store[ip].append(now)
    return True

# ──────────────────────────────────────────────
# SECURITY: Response headers
# ──────────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    return response

@app.before_request
def enforce_rate_limit():
    if not check_rate_limit():
        abort(429, description="Rate limit exceeded")

# ──────────────────────────────────────────────
# Global storage
# ──────────────────────────────────────────────
packets_list = []
alerts = []
dns_cache = {}           # IP -> domain reverse lookup
dns_query_log = []       # Recent DNS queries
process_cache = {}       # (port, proto) -> process_name
connection_tracker = {}  # (src, dst, port) -> count
protocol_stats = defaultdict(int)   # protocol_name -> count
app_bandwidth = defaultdict(int)    # app_name -> total_bytes
domain_hits = defaultdict(int)      # domain -> count
category_stats = defaultdict(int)   # category -> count
sniffing = False
sniffer_thread = None
capture_start_time = None
stop_event = threading.Event()  # Used to signal the sniffer to stop cleanly
total_bytes = 0
sniffer_error = None

MAX_PACKETS = 1000
MAX_ALERTS = 1000
MAX_DNS_LOG = 200

# ──────────────────────────────────────────────
# Well-known port -> protocol mapping
# ──────────────────────────────────────────────
PORT_PROTOCOL_MAP = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    465: "SMTPS", 587: "SMTP", 853: "DNS-over-TLS",
    993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1194: "OpenVPN", 1723: "PPTP",
    3306: "MySQL", 3389: "RDP", 5060: "SIP", 5061: "SIPS",
    1080: "SOCKS", 1194: "OpenVPN", 1723: "PPTP",
    3306: "MySQL", 3389: "RDP", 5060: "SIP", 5061: "SIPS",
    5222: "XMPP", 5223: "XMPP-SSL", 5228: "Google-Push",
    5353: "mDNS", 5432: "PostgreSQL",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    6881: "BitTorrent", 6882: "BitTorrent", 6883: "BitTorrent",
    27017: "MongoDB", 6379: "Redis",
    443: "HTTPS", # Fallback, handled by logic usually
}

# Add QUIC identification
def identify_protocol(packet):
    """
    Determine the application-layer protocol by examining ports.
    Falls back to transport-layer (TCP/UDP/ICMP/ARP) if unknown.
    """
    if packet.haslayer(DNS):
        return "DNS"

    if packet.haslayer(TCP):
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        return PORT_PROTOCOL_MAP.get(dport) or PORT_PROTOCOL_MAP.get(sport) or "TCP"

    if packet.haslayer(UDP):
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        if dport == 443 or sport == 443:
            return "QUIC"
        return PORT_PROTOCOL_MAP.get(dport) or PORT_PROTOCOL_MAP.get(sport) or "UDP"

    if packet.haslayer(ICMP):
        return "ICMP"

    if packet.haslayer(ARP):
        return "ARP"

    return "Other"

# ──────────────────────────────────────────────
# Traffic categories based on protocol / port
# ──────────────────────────────────────────────
TRAFFIC_CATEGORIES = {
    "Browsing":   {"HTTP", "HTTPS", "HTTP-Proxy", "HTTPS-Alt"},
    "Email":      {"SMTP", "SMTPS", "IMAP", "IMAPS", "POP3", "POP3S"},
    "File Transfer": {"FTP", "FTP-Data"},
    "Remote":     {"SSH", "Telnet", "RDP"},
    "DNS":        {"DNS", "DNS-over-TLS", "mDNS"},
    "VPN/Proxy":  {"OpenVPN", "PPTP", "SOCKS"},
    "Messaging":  {"XMPP", "XMPP-SSL", "Google-Push", "SIP", "SIPS"},
    "Database":   {"MySQL", "PostgreSQL", "MongoDB", "Redis"},
    "P2P":        {"BitTorrent"},
    "DHCP":       {"DHCP"},
}

BROWSERS = {
    "Google Chrome", "Safari", "Firefox", "Brave Browser", "Arc", "Microsoft Edge",
    "Google Chro", "Brave Brows", "Firefox CP", "WebKit", "com.apple.Safar"
}

# Session tracking
active_sessions = {} # (dst_ip, app) -> {start_time, domain, flags}

def get_category(protocol_name):
    """Classify a protocol into a human-readable traffic category."""
    # Ensure protocol names are mapped correctly
    for category, protos in TRAFFIC_CATEGORIES.items():
        if protocol_name in protos:
            return category
    if protocol_name in ("HTTP", "HTTPS", "DNS", "QUIC"):
        return "Browsing"
    return "Other"


# ──────────────────────────────────────────────
# Known domain -> service mapping (for enrichment)
# ──────────────────────────────────────────────
DOMAIN_SERVICES = {
    "google": "Google", "youtube": "YouTube", "facebook": "Facebook",
    "instagram": "Instagram", "twitter": "Twitter", "x.com": "X/Twitter",
    "whatsapp": "WhatsApp", "netflix": "Netflix", "spotify": "Spotify",
    "apple": "Apple", "icloud": "iCloud", "microsoft": "Microsoft",
    "outlook": "Outlook", "github": "GitHub", "amazon": "Amazon",
    "aws": "AWS", "cloudflare": "Cloudflare", "discord": "Discord",
    "telegram": "Telegram", "zoom": "Zoom", "slack": "Slack",
    "reddit": "Reddit", "tiktok": "TikTok", "linkedin": "LinkedIn",
    "gmail": "Gmail", "yahoo": "Yahoo",
    "steam": "Steam", "twitch": "Twitch",
}

def identify_service(domain):
    """Try to identify a known service from a domain string."""
    if not domain:
        return None
    domain_lower = domain.lower()
    for key, service in DOMAIN_SERVICES.items():
        if key in domain_lower:
            return service
    return None


# ──────────────────────────────────────────────
# Process mapping (macOS)
# ──────────────────────────────────────────────
def update_process_map():
    """Polls system networking to map ports to process names (cross-platform)."""
    global process_cache
    new_cache = {}
    
    if os.name == 'nt':  # Windows
        try:
            # Get connections and PIDs
            output = subprocess.check_output(["netstat", "-ano"], stderr=subprocess.STDOUT).decode()
            pids = {}
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 5:
                    # Proto Local_Addr Remote_Addr State PID
                    proto = parts[0] # TCP or UDP
                    local_addr = parts[1]
                    pid = parts[-1]
                    if ':' in local_addr:
                        port = local_addr.split(':')[-1]
                        pids[(port, proto)] = pid

            # Get process names for PIDs
            if pids:
                task_output = subprocess.check_output(["tasklist", "/NH", "/FO", "CSV"], stderr=subprocess.STDOUT).decode()
                name_map = {}
                for line in task_output.splitlines():
                    if not line.strip(): continue
                    # "Image Name","PID","Session Name","Session#","Mem Usage"
                    p_parts = line.replace('"', '').split(',')
                    if len(p_parts) >= 2:
                        name_map[p_parts[1]] = p_parts[0]
                
                for (port, proto), pid in pids.items():
                    if pid in name_map:
                        new_cache[(port, proto)] = name_map[pid]
            process_cache = new_cache
        except Exception:
            pass
    else:  # macOS / Linux
        try:
            output = subprocess.check_output(
                ["lsof", "-i", "-n", "-P"], stderr=subprocess.STDOUT
            ).decode()
            for line in output.splitlines()[1:]:
                parts = line.split()
                if len(parts) > 8:
                    pid = parts[1]
                    port = parts[8].split(':')[-1]
                    proto = parts[7]  # TCP or UDP

                    try:
                        full_name = subprocess.check_output(
                            ["ps", "-p", pid, "-o", "comm="], stderr=subprocess.DEVNULL
                        ).decode().strip()
                        process = os.path.basename(full_name) if full_name else parts[0]
                    except Exception:
                        process = parts[0]

                    new_cache[(port, proto)] = process
            process_cache = new_cache
        except Exception:
            pass


def get_process_for_packet(packet):
    """Attempt to find the app name for a given packet."""
    proto = None
    if packet.haslayer(TCP):
        layer = packet[TCP]
        proto = "TCP"
    elif packet.haslayer(UDP):
        layer = packet[UDP]
        proto = "UDP"
    else:
        return "System"

    src_port = str(layer.sport)
    dst_port = str(layer.dport)

    return (
        process_cache.get((src_port, proto))
        or process_cache.get((dst_port, proto))
        or "Unknown"
    )


# ──────────────────────────────────────────────
# DNS resolution
# ──────────────────────────────────────────────
def resolve_dns_bg(ip):
    """Background worker for DNS resolution."""
    global dns_pending
    try:
        domain = socket.gethostbyaddr(ip)[0]
        dns_cache[ip] = domain
    except Exception:
        dns_cache[ip] = ip # Fallback to IP
    finally:
        if ip in dns_pending:
            dns_pending.remove(ip)

def get_domain(ip):
    """Reverse DNS lookup with caching and async background resolution."""
    if not ip:
        return None
    if ip in dns_cache:
        return dns_cache[ip]
    
    # If not in cache and not already pending, dispatch to background
    if ip not in dns_pending:
        dns_pending.add(ip)
        dns_executor.submit(resolve_dns_bg, ip)
    
    return ip # Return IP immediately; domain will appear in later packets once resolved


# ──────────────────────────────────────────────
# TLS SNI extraction (reads domain from ClientHello — NO decryption)
# ──────────────────────────────────────────────
def extract_tls_sni(payload):
    """
    Parse TLS ClientHello to extract Server Name Indication.
    This reads the unencrypted handshake header only — 
    the actual encrypted content is never touched.
    """
    try:
        if len(payload) < 6:
            return None
        # TLS record: content_type(1) + version(2) + length(2) + ...
        content_type = payload[0]
        if content_type != 0x16:  # Not a handshake
            return None

        # Handshake type should be ClientHello (0x01)
        if len(payload) < 6 or payload[5] != 0x01:
            return None

        # Walk through the ClientHello to find SNI extension
        # Skip: handshake header(5) + handshake_type(1) + length(3) + version(2) + random(32)
        offset = 5 + 1 + 3 + 2 + 32
        if offset + 1 >= len(payload):
            return None

        # Session ID length
        session_id_len = payload[offset]
        offset += 1 + session_id_len

        if offset + 2 >= len(payload):
            return None

        # Cipher suites length
        cipher_suites_len = struct.unpack("!H", payload[offset:offset + 2])[0]
        offset += 2 + cipher_suites_len

        if offset >= len(payload):
            return None

        # Compression methods length
        comp_methods_len = payload[offset]
        offset += 1 + comp_methods_len

        if offset + 2 >= len(payload):
            return None

        # Extensions length
        extensions_len = struct.unpack("!H", payload[offset:offset + 2])[0]
        offset += 2
        extensions_end = offset + extensions_len

        while offset + 4 < extensions_end and offset + 4 < len(payload):
            ext_type = struct.unpack("!H", payload[offset:offset + 2])[0]
            ext_len = struct.unpack("!H", payload[offset + 2:offset + 4])[0]
            offset += 4

            if ext_type == 0x0000:  # SNI extension
                if offset + 5 < len(payload):
                    # SNI list length(2) + type(1) + name_length(2)
                    sni_name_len = struct.unpack("!H", payload[offset + 3:offset + 5])[0]
                    sni_name = payload[offset + 5:offset + 5 + sni_name_len]
                    return sni_name.decode("ascii", errors="ignore")
            offset += ext_len

    except Exception:
        pass
    return None


# ──────────────────────────────────────────────
# HTTP Host extraction (plaintext HTTP only)
# ──────────────────────────────────────────────
def extract_http_info(payload_str):
    """Extract method, path, and Host header from plaintext HTTP."""
    info = {}
    try:
        lines = payload_str.split('\r\n')
        if lines:
            first = lines[0]
            # Check if it's an HTTP request line like "GET /path HTTP/1.1"
            http_match = re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT)\s+(\S+)\s+HTTP/', first)
            if http_match:
                info["method"] = http_match.group(1)
                info["path"] = http_match.group(2)[:80]  # truncate long paths

            for line in lines[1:]:
                if line.lower().startswith("host:"):
                    info["host"] = line.split(":", 1)[1].strip()
                    break
    except Exception:
        pass
    return info


# ──────────────────────────────────────────────
# Sensitive data patterns (lightweight — only plaintext leaks)
# These detect data accidentally sent in the clear, which is
# a legitimate security concern. No encrypted traffic is touched.
# ──────────────────────────────────────────────
PATTERNS = {
    "Credentials": re.compile(
        r'(password|passwd|pwd|secret|login|auth|session|token)'
        r'["\s:=]+([a-zA-Z0-9.\-_~]{6,})', re.I
    ),
    "API Key": re.compile(
        r'(?:AIza[0-9A-Za-z\-_]{35})|(?:sk-[a-zA-Z0-9]{20,})', re.I
    ),
    "Email Address": re.compile(
        r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
    ),
    "Credit Card": re.compile(r'\b(?:\d[ -]*?){13,16}\b'),
}


def luhn_check(card_number):
    """Verifies a credit card number using the Luhn algorithm."""
    digits = [int(d) for d in re.sub(r'\D', '', card_number)]
    if len(digits) < 13:
        return False
    checksum = digits[-1]
    total = 0
    for i, digit in enumerate(reversed(digits[:-1])):
        if i % 2 == 0:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return (total + checksum) % 10 == 0


def mask_sensitive(content, label):
    """Redact sensitive data so it's never stored in full."""
    if not content:
        return "[REDACTED]"
    s = str(content)
    if label == "Credit Card":
        # Show only last 4 digits: ****-****-****-1234
        digits = re.sub(r'\D', '', s)
        return f"****-****-****-{digits[-4:]}" if len(digits) >= 4 else "****"
    elif label == "Email Address":
        # user@domain -> u***r@d***n
        parts = s.split("@")
        if len(parts) == 2:
            u = parts[0][0] + "***" + (parts[0][-1] if len(parts[0]) > 1 else "")
            d = parts[1][0] + "***" + parts[1][-3:] if len(parts[1]) > 3 else parts[1]
            return f"{u}@{d}"
        return s[:3] + "***"
    elif label == "API Key":
        # Show only first 4 and last 4 chars
        return s[:4] + "****" + s[-4:] if len(s) > 8 else "****"
    elif label == "Credentials":
        # Show the field name but mask the value
        return s[:8] + "***[MASKED]" if len(s) > 8 else "***[MASKED]"
    return s[:6] + "***"


def inspect_payload(payload_str, packet_info):
    """Check plaintext payloads for accidentally exposed sensitive data."""
    # Ignore multicast / noise
    if packet_info.get("dst_ip", "").startswith("239."):
        return

    for label, pattern in PATTERNS.items():
        matches = pattern.findall(payload_str)
        for match in matches:
            content = (
                str(match) if isinstance(match, (str, bytes))
                else str(match[0] if match else "")
            )

            if label == "Credit Card" and not luhn_check(content):
                continue

            # SECURITY: Mask the detected content before storing
            masked = mask_sensitive(content, label)
            severity = "critical" if label in ("Credit Card", "Credentials") else "warning"
            
            # Risk Assessment
            is_external = not (packet_info["dst_ip"].startswith("192.168.") or 
                              packet_info["dst_ip"].startswith("10.") or 
                              packet_info["dst_ip"].startswith("127.0.0.1"))
            
            threat_assessment = "THREAT" if is_external else "INFO / FINE"
            if severity == "critical": threat_assessment = "CRITICAL THREAT"

            add_alert(
                f"Leak Detected: {label}", 
                severity, 
                packet_info, 
                f"{label} exposed to {packet_info['dst_ip']}\nPattern: {masked}\nAssessment: {threat_assessment}"
            )

def detect_anomalies(packet, packet_info):
    """Detect suspicious network behavior and TCP flag anomalies."""
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        flags = str(tcp.flags)  # tcp.flags is a FlagValue — str() gives e.g. "SA", "S", "FA"
        # Scapy flags: F=FIN, S=SYN, R=RST, P=PSH, A=ACK, U=URG, E=ECE, C=CWR
        
        # Null Scan (No flags)
        if tcp.flags == 0:
            add_alert("Security Flag: Null Scan", "critical", packet_info, "TCP packet with no flags set (highly suspicious reconnaissance)")
        
        # Xmas Scan (FIN, PSH, URG)
        elif tcp.flags == 0x29: # FIN (1) + PSH (8) + URG (32)
            add_alert("Security Flag: Xmas Scan", "critical", packet_info, "TCP packet with FIN, PSH, and URG flags set (reconnaissance)")
        
        # SYN-FIN (Illegal combination)
        elif (tcp.flags & 0x01) and (tcp.flags & 0x02):
            add_alert("Security Flag: SYN-FIN", "critical", packet_info, "TCP packet with both SYN and FIN flags set (firewall bypass attempt)")

        # RST (Reset) - could indicate blocked port or attack
        elif tcp.flags & 0x04:
            add_alert("Network Flag: RST (Reset)", "warning", packet_info, f"Connection reset by {packet_info['src_ip']}. Could indicate a closed port or dropped connection.")

        # URG (Urgent) - rarely used, can be suspicious
        elif tcp.flags & 0x20:
            add_alert("Network Flag: URG (Urgent)", "warning", packet_info, "Urgent pointer set. Unusual in modern traffic, could be OOB data manipulation.")

        # General Flag Logging (Low priority for everything else interesting)
        elif tcp.flags & 0x01: # FIN
            add_alert("Network Flag: FIN", "warning", packet_info, "Connection termination request initiated (FIN flag). Assessment: FINE / NORMAL")
        
        elif tcp.flags & 0x02 and not (tcp.flags & 0x10): # SYN without ACK
            add_alert("Network Flag: SYN", "warning", packet_info, f"New connection request (SYN) from {packet_info['src_ip']}. Assessment: INFO / FINE")

    if packet.haslayer(ICMP):
        icmp = packet[ICMP]
        if icmp.type == 5: # Redirect
            add_alert("Security Flag: ICMP Redirect", "critical", packet_info, "ICMP Redirect detected. Potential Man-in-the-Middle (MITM) attempt!")
        elif icmp.type == 8: # Echo Request
            add_alert("Network Flag: Ping (Echo)", "warning", packet_info, f"ICMP Echo Request (Ping) from {packet_info['src_ip']}. Assessment: INFO / FINE")

    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode(errors="ignore").upper()
            # Check for plaintext credentials in email protocols
            # Use packet_info["protocol"] — 'protocol' is not in this function's scope
            pkt_protocol = packet_info.get("protocol", "")
            if "AUTH LOGIN" in payload or "USER " in payload or "PASS " in payload:
                if pkt_protocol in ("SMTP", "POP3", "IMAP"):
                    add_alert("Email Flag: Plaintext Auth", "critical", packet_info, f"Plaintext authentication command detected in {pkt_protocol} traffic")
        except:
            pass

    if packet.haslayer(ARP):
        arp = packet[ARP]
        if arp.op == 2: # ARP Reply
            # Simple Gratuitous ARP check or potential Spoofing
            pass # Needs stateful tracking of IP-MAC pairs

def track_web_visit(packet, packet_info):
    """Senses and records website visits from browsers (TCP & QUIC/UDP)."""
    app = packet_info.get("app", "Unknown")
    protocol = packet_info.get("protocol")
    
    # Check if it's a browser OR if it's traffic on web ports
    is_web_port = protocol in ("HTTP", "HTTPS", "HTTP-Proxy", "HTTPS-Alt", "UDP")
    if protocol == "UDP" and packet.haslayer(UDP) and packet[UDP].dport != 443:
        is_web_port = False

    is_known_browser = any(b in app for b in BROWSERS)
    
    if not (is_known_browser or (is_web_port and app == "Unknown")):
        return

    if app == "Unknown" and is_web_port:
        app = "Web Browser (Auto)"
        packet_info["app"] = app

    dst_ip = packet_info["dst_ip"]
    domain = packet_info.get("dst_domain") or dst_ip
    
    # 1. Sense the START of a visit
    is_start = False
    # TCP SYN
    if packet.haslayer(TCP) and (packet[TCP].flags & 0x02) and not (packet[TCP].flags & 0x10):
        is_start = True
    # QUIC (UDP 443) - First packet seen for this destination
    elif protocol == "UDP" and packet.haslayer(UDP) and packet[UDP].dport == 443:
        if (dst_ip, app) not in active_sessions:
            is_start = True

    if is_start:
        add_alert(
            "Site Visit Sensed", 
            "warning", 
            packet_info, 
            f"Security Audit: {app} is opening a connection to {domain}.\nAssessment: SENSING START"
        )

    # 2. Record the visit when domain is known
    # Catch-all: even if we missed the 'Start' (SYN/QUIC initial), record it when we see a domain
    if domain and domain != dst_ip:
        session_key = (domain, app)
        if session_key not in active_sessions:
            active_sessions[session_key] = True
            add_alert(
                "Site Visit Recorded", 
                "warning", 
                packet_info, 
                f"Audit Complete: {app} successfully connected to {domain}.\nStatus: RECORDED\nAssessment: INFO / FINE"
            )

def add_alert(alert_type, severity, packet_info, content):
    """Helper to add a security alert."""
    seriousness = "HIGH" if severity == "critical" else "MEDIUM"
    if "FINE" in content: seriousness = "LOW"
    
    alert = {
        "id": len(alerts) + 1,
        "time": packet_info["time"],
        "type": alert_type,
        "severity": severity,
        "seriousness": seriousness,
        "is_threat": seriousness != "LOW",
        "src": packet_info["src_ip"],
        "dst": packet_info["dst_ip"],
        "app": packet_info.get("app", "Unknown"),
        "dst_domain": packet_info.get("dst_domain"),
        "content": content,
        "protocol": packet_info.get("protocol", ""),
        "category": packet_info.get("category", "Other"),
    }
    alerts.append(alert)
    if len(alerts) > MAX_ALERTS:
        alerts.pop(0)


# identify_protocol is defined earlier (with QUIC detection). No duplicate needed here.


# ──────────────────────────────────────────────
# Core packet processor
# ──────────────────────────────────────────────
def process_packet(packet):
    global total_bytes

    # Handle ARP (no IP layer)
    if packet.haslayer(ARP):
        arp = packet[ARP]
        pkt_size = len(packet)
        total_bytes += pkt_size
        protocol_stats["ARP"] += 1
        category_stats["Network"] += 1

        packet_info = {
            "id": len(packets_list) + 1,
            "time": datetime.datetime.now().strftime("%H:%M:%S"),
            "src_ip": arp.psrc,
            "dst_ip": arp.pdst,
            "app": "System",
            "src_domain": None,
            "dst_domain": None,
            "protocol": "ARP",
            "category": "Network",
            "service": None,
            "size": pkt_size,
            "info": f"Who has {arp.pdst}?" if arp.op == 1 else f"{arp.psrc} is at {arp.hwsrc}",
        }
        packets_list.append(packet_info)
        
        # Check for ARP anomalies
        detect_anomalies(packet, packet_info)
        
        if len(packets_list) > MAX_PACKETS:
            packets_list.pop(0)
        return

    if not packet.haslayer(IP) and not packet.haslayer(IPv6):
        return

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
    else:
        ip_layer = packet[IPv6]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
    pkt_size = len(packet)
    total_bytes += pkt_size

    # Identify protocol
    protocol = identify_protocol(packet)
    category = get_category(protocol)
    protocol_stats[protocol] += 1
    category_stats[category] += 1

    # Get process name
    app_name = get_process_for_packet(packet)
    app_bandwidth[app_name] += pkt_size

    # Resolve domains
    dst_domain = get_domain(dst_ip)
    src_domain = get_domain(src_ip)

    # Extra info string
    extra_info = None
    sni_domain = None

    # DNS query/response details
    if packet.haslayer(DNS):
        if packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
            extra_info = f"Query: {qname}"
            # Cache DNS response for future lookups
            if packet.haslayer(DNSRR):
                try:
                    rdata = packet[DNSRR].rdata
                    if isinstance(rdata, bytes):
                        rdata = rdata.decode(errors="ignore")
                    if rdata:
                        dns_cache[str(rdata)] = qname
                except Exception:
                    pass

            dns_query_log.append({
                "time": datetime.datetime.now().strftime("%H:%M:%S"),
                "query": qname,
                "src": src_ip,
            })
            if len(dns_query_log) > MAX_DNS_LOG:
                dns_query_log.pop(0)

    # TLS SNI extraction (for HTTPS traffic — reads handshake header only)
    if protocol in ("HTTPS", "HTTPS-Alt") and packet.haslayer(Raw):
        try:
            sni = extract_tls_sni(bytes(packet[Raw].load))
            if sni:
                sni_domain = sni
                # Use SNI as the domain if reverse DNS didn't find anything useful
                if not dst_domain or dst_domain == dst_ip:
                    dst_domain = sni
                # Cache this for future packets to the same IP
                dns_cache[dst_ip] = sni
                extra_info = f"SNI: {sni}"
        except Exception:
            pass

    # HTTP host extraction (plaintext only)
    if protocol in ("HTTP", "HTTP-Proxy") and packet.haslayer(Raw):
        try:
            payload_str = packet[Raw].load.decode(errors="ignore")
            http_info = extract_http_info(payload_str)
            if http_info.get("host"):
                dst_domain = http_info["host"]
                dns_cache[dst_ip] = http_info["host"]
            if http_info.get("method"):
                path = http_info.get("path", "")
                extra_info = f"{http_info['method']} {path}"

            # Check plaintext for accidentally exposed sensitive data (HTTP and Email)
            inspect_payload(payload_str, {
                "time": datetime.datetime.now().strftime("%H:%M:%S"),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "app": app_name,
                "dst_domain": dst_domain,
                "protocol": protocol,
                "category": category,
            })
        except Exception:
            pass

    # SMTP/IMAP/POP3 specific inspection (if not already handled above)
    if protocol in ("SMTP", "POP3", "IMAP") and packet.haslayer(Raw):
        try:
            payload_str = packet[Raw].load.decode(errors="ignore")
            # If it's SMTP/POP3/IMAP, it might contain email addresses or logins
            inspect_payload(payload_str, {
                "time": datetime.datetime.now().strftime("%H:%M:%S"),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "app": app_name,
                "dst_domain": dst_domain,
                "protocol": protocol,
                "category": category,
            })
            extra_info = f"Mail Data ({protocol})"
        except Exception:
            pass

    # Track domain hits
    if dst_domain:
        domain_hits[dst_domain] += 1

    # Identify known service
    service = identify_service(dst_domain) or identify_service(sni_domain)

    # Track connections
    conn_key = (src_ip, dst_ip, protocol)
    connection_tracker[conn_key] = connection_tracker.get(conn_key, 0) + 1

    # Extract TCP flags for display
    tcp_flags = None
    if packet.haslayer(TCP):
        tcp_flags = str(packet[TCP].flags)  # FlagValue — gives "S", "SA", "FA" etc.

    # Build packet info
    packet_info = {
        "id": len(packets_list) + 1,
        "time": datetime.datetime.now().strftime("%H:%M:%S"),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "app": app_name,
        "src_domain": src_domain,
        "dst_domain": dst_domain,
        "protocol": protocol,
        "flags": tcp_flags,
        "category": category,
        "service": service,
        "size": pkt_size,
        "info": extra_info,
    }

    # Run anomaly detection and web visit tracking
    detect_anomalies(packet, packet_info)
    track_web_visit(packet, packet_info)

    packets_list.append(packet_info)
    if len(packets_list) > MAX_PACKETS:
        packets_list.pop(0)


# ──────────────────────────────────────────────
# Sniffer engine
# ──────────────────────────────────────────────
def start_sniffer():
    global capture_start_time, sniffing, sniffer_error
    print("⚡ Sniffer engine starting...")
    capture_start_time = datetime.datetime.now()
    stop_event.clear()

    # Process map updater
    def mapper_loop():
        while not stop_event.is_set():
            update_process_map()
            time.sleep(2)

    threading.Thread(target=mapper_loop, daemon=True).start()

    # Use timeout= so sniff() returns every second and we can check stop_event.
    def should_stop(x):
        return stop_event.is_set()

    try:
        # Interface selection
        target_iface = "en0" if os.name != 'nt' else None # On Windows, let Scapy pick default or we can try to find one
        
        print(f"🔍 Attempting to sniff on {target_iface or 'default interface'}...")
        while not stop_event.is_set():
            sniff(
                iface=target_iface,
                prn=process_packet,
                store=False,
                timeout=1,
                stop_filter=should_stop,
            )
    except Exception as e:
        print(f"⚠️ Initial sniff failed ({e}), falling back to default interface...")
        try:
            while not stop_event.is_set():
                sniff(
                    prn=process_packet,
                    store=False,
                    timeout=1,
                    stop_filter=should_stop,
                )
        except Exception as e2:
            print(f"❌ Sniffer error: {e2}")
            sniffer_error = str(e2)
            sniffing = False


# ──────────────────────────────────────────────
# API Routes
# ──────────────────────────────────────────────
# ──────────────────────────────────────────────
# SECURITY: Auto-expiry — purge data older than 10 min
# ──────────────────────────────────────────────
def auto_expiry_loop():
    """Periodically trim old data to prevent memory bloat and data leakage."""
    while True:
        time.sleep(120)  # Run every 2 minutes
        now = datetime.datetime.now()
        cutoff = (now - datetime.timedelta(minutes=10)).strftime("%H:%M:%S")
        # Trim packets older than cutoff (simple time string comparison)
        while packets_list and packets_list[0].get("time", "99") < cutoff:
            packets_list.pop(0)
        while dns_query_log and dns_query_log[0].get("time", "99") < cutoff:
            dns_query_log.pop(0)


# ──────────────────────────────────────────────
# API Routes (all require auth token)
# ──────────────────────────────────────────────
@app.route("/api/start", methods=["POST"])
@require_auth
def start_capture():
    global sniffer_thread, sniffing, total_bytes
    if not sniffing:
        sniffing = True
        total_bytes = 0
        stop_event.clear()
        sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
        sniffer_thread.start()
    return jsonify({"status": "sniffing started"})


@app.route("/api/stop", methods=["POST"])
@require_auth
def stop_capture():
    global sniffing
    sniffing = False
    stop_event.set()  # Signal the sniffer loop to exit cleanly
    return jsonify({"status": "sniffing stopped"})


@app.route("/api/status", methods=["GET"])
@require_auth
def get_status():
    uptime = None
    if capture_start_time and sniffing:
        delta = datetime.datetime.now() - capture_start_time
        uptime = str(delta).split(".")[0]  # HH:MM:SS

    return jsonify({
        "sniffing": sniffing,
        "packet_count": len(packets_list),
        "alert_count": len(alerts),
        "total_bytes": total_bytes,
        "unique_connections": len(connection_tracker),
        "unique_domains": len(set(p.get("dst_domain") for p in packets_list if p.get("dst_domain"))),
        "uptime": uptime,
        "error": sniffer_error
    })


@app.route("/api/packets", methods=["GET"])
@require_auth
def get_packets():
    count = min(request.args.get("count", 50, type=int), 200)  # Cap at 200
    protocol_filter = request.args.get("protocol", None)
    category_filter = request.args.get("category", None)

    result = packets_list
    if protocol_filter:
        result = [p for p in result if p["protocol"] == protocol_filter]
    if category_filter:
        result = [p for p in result if p["category"] == category_filter]

    return jsonify(result[-count:])


@app.route("/api/alerts", methods=["GET"])
@require_auth
def get_alerts():
    return jsonify(alerts[-30:])


@app.route("/api/stats", methods=["GET"])
@require_auth
def get_stats():
    """Rich statistics for the dashboard."""
    top_domains = sorted(domain_hits.items(), key=lambda x: x[1], reverse=True)[:10]
    top_apps = sorted(app_bandwidth.items(), key=lambda x: x[1], reverse=True)[:10]
    proto_dist = dict(sorted(protocol_stats.items(), key=lambda x: x[1], reverse=True)[:15])
    cat_dist = dict(sorted(category_stats.items(), key=lambda x: x[1], reverse=True))

    return jsonify({
        "protocol_distribution": proto_dist,
        "category_distribution": cat_dist,
        "top_domains": [{"domain": d, "count": c} for d, c in top_domains],
        "top_apps": [{"app": a, "bytes": b} for a, b in top_apps],
        "total_bytes": total_bytes,
        "total_packets": len(packets_list),
        "unique_connections": len(connection_tracker),
    })


@app.route("/api/dns", methods=["GET"])
@require_auth
def get_dns_log():
    """Recent DNS queries — shows what domains your machine is looking up."""
    return jsonify(dns_query_log[-50:])


@app.route("/api/clear", methods=["POST"])
@require_auth
def clear_data():
    """Reset all captured data."""
    global total_bytes
    packets_list.clear()
    alerts.clear()
    dns_query_log.clear()
    connection_tracker.clear()
    protocol_stats.clear()
    app_bandwidth.clear()
    domain_hits.clear()
    category_stats.clear()
    total_bytes = 0
    return jsonify({"status": "cleared"})


# ──────────────────────────────────────────────
# Token endpoint (no auth needed — used by frontend on startup)
# ──────────────────────────────────────────────
@app.route("/api/token", methods=["GET"])
def get_token():
    """Returns the API token. Only accessible from localhost."""
    if request.remote_addr not in ("127.0.0.1", "::1"):
        abort(403, description="Token only available from localhost")
    return jsonify({"token": API_TOKEN})


if __name__ == "__main__":
    write_token()
    # Start auto-expiry daemon
    threading.Thread(target=auto_expiry_loop, daemon=True).start()
    print(f"🛡️  Packet Sniffer API running on http://127.0.0.1:8000")
    print(f"🔐 Auth token: {API_TOKEN[:8]}...")
    try:
        app.run(host="127.0.0.1", port=8000)
    except KeyboardInterrupt:
        pass
    finally:
        # Signal sniffer to stop and shut down the DNS thread pool cleanly.
        # Without this, Python throws "cannot schedule new futures after
        # interpreter shutdown" warnings when Ctrl+C is pressed.
        stop_event.set()
        sniffing = False
        dns_executor.shutdown(wait=False, cancel_futures=True)
        print("\n🛑 Packet Sniffer stopped cleanly.")