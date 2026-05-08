import threading
import datetime
import re
import socket
import os
import subprocess
import struct
import time
import secrets
import itertools
from collections import defaultdict, OrderedDict
from concurrent.futures import ThreadPoolExecutor
from functools import wraps

from scapy.all import (
    sniff, IP, IPv6, TCP, UDP, DNS, DNSQR, DNSRR, ICMP, ARP, Raw, Ether, conf
)
from flask import Flask, jsonify, request, abort
from flask_cors import CORS
import logging

app = Flask(__name__)

CORS(app, origins=[
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "app://.",
])

log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)


# ──────────────────────────────────────────────────────────────────────────────
# Auth
# ──────────────────────────────────────────────────────────────────────────────
API_TOKEN   = secrets.token_hex(32)
TOKEN_FILE  = os.path.join(os.path.dirname(__file__), ".api_token")


def write_token() -> None:
    with open(TOKEN_FILE, "w") as f:
        f.write(API_TOKEN)
    try:
        os.chmod(TOKEN_FILE, 0o644)
    except OSError:
        pass
    print(f"🔐 API token written to {TOKEN_FILE}")


def require_auth(f):
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
_rate_lock        = threading.Lock()
_rate_limit_store: dict[str, list[float]] = defaultdict(list)
RATE_LIMIT        = 1000
RATE_WINDOW       = 60   # seconds


def check_rate_limit() -> bool:
    ip  = request.remote_addr or "unknown"
    now = time.monotonic()
    with _rate_lock:
        _rate_limit_store[ip] = [
            t for t in _rate_limit_store[ip] if now - t < RATE_WINDOW
        ]
        if len(_rate_limit_store[ip]) >= RATE_LIMIT:
            return False
        _rate_limit_store[ip].append(now)
    return True


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]          = "DENY"
    response.headers["X-XSS-Protection"]         = "1; mode=block"
    response.headers["Cache-Control"]            = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"]                   = "no-cache"
    return response


@app.before_request
def enforce_rate_limit():
    if not check_rate_limit():
        abort(429, description="Rate limit exceeded")


# ──────────────────────────────────────────────────────────────────────────────
# Limits
# ──────────────────────────────────────────────────────────────────────────────
MAX_PACKETS    = 1000
MAX_ALERTS     = 1000
MAX_DNS_LOG    = 200
MAX_DNS_CACHE  = 5000   # LRU cap — prevents unbounded growth
MAX_SESSIONS   = 2000   # active_sessions cap


# ──────────────────────────────────────────────────────────────────────────────
# Shared state + one RLock that guards all of it
#
# RLock (re-entrant) is used so that helpers called from process_packet
# (which already holds no lock itself) can call add_alert safely, and
# add_alert in turn can safely append to alerts without deadlocking.
# ──────────────────────────────────────────────────────────────────────────────
_lock = threading.RLock()

packets_list:       list[dict]              = []
alerts:             list[dict]              = []
dns_query_log:      list[dict]              = []
process_cache:      dict[tuple, str]        = {}
connection_tracker: dict[tuple, int]        = {}
protocol_stats:     dict[str, int]          = defaultdict(int)
app_bandwidth:      dict[str, int]          = defaultdict(int)
domain_hits:        dict[str, int]          = defaultdict(int)
category_stats:     dict[str, int]          = defaultdict(int)
active_sessions:    dict[tuple, bool]       = {}

# LRU DNS cache — guarded by _lock
dns_cache: OrderedDict[str, str] = OrderedDict()

# dns_pending uses its own lock so DNS submissions don't contend with
# the main sniffer lock during background resolution.
_dns_pending_lock = threading.Lock()
_dns_pending:     set[str] = set()

# Atomic alert ID counter — itertools.count is thread-safe in CPython
_alert_id_counter = itertools.count(1)

# Sniffer state — only written under _state_lock
_state_lock   = threading.Lock()
sniffing      = False
sniffer_error: str | None = None

capture_start_time: datetime.datetime | None = None
total_bytes   = 0                   # guarded by _lock
stop_event    = threading.Event()
sniffer_thread: threading.Thread | None = None

# DNS background thread pool
dns_executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix="dns-resolver")


# ──────────────────────────────────────────────────────────────────────────────
# Port → protocol map  (no duplicate keys)
# ──────────────────────────────────────────────────────────────────────────────
PORT_PROTOCOL_MAP: dict[int, str] = {
    20:    "FTP-Data",
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    67:    "DHCP",
    68:    "DHCP",
    80:    "HTTP",
    110:   "POP3",
    143:   "IMAP",
    443:   "HTTPS",
    465:   "SMTPS",
    587:   "SMTP",
    853:   "DNS-over-TLS",
    993:   "IMAPS",
    995:   "POP3S",
    1080:  "SOCKS",
    1194:  "OpenVPN",
    1723:  "PPTP",
    3306:  "MySQL",
    3389:  "RDP",
    5060:  "SIP",
    5061:  "SIPS",
    5222:  "XMPP",
    5223:  "XMPP-SSL",
    5228:  "Google-Push",
    5353:  "mDNS",
    5432:  "PostgreSQL",
    6379:  "Redis",
    6881:  "BitTorrent",
    6882:  "BitTorrent",
    6883:  "BitTorrent",
    8080:  "HTTP-Proxy",
    8443:  "HTTPS-Alt",
    27017: "MongoDB",
}


def identify_protocol(packet) -> str:
    if packet.haslayer(DNS):
        return "DNS"

    if packet.haslayer(TCP):
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        return PORT_PROTOCOL_MAP.get(dport) or PORT_PROTOCOL_MAP.get(sport) or "TCP"

    if packet.haslayer(UDP):
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        # QUIC runs on UDP/443
        if dport == 443 or sport == 443:
            return "QUIC"
        return PORT_PROTOCOL_MAP.get(dport) or PORT_PROTOCOL_MAP.get(sport) or "UDP"

    if packet.haslayer(ICMP):
        return "ICMP"

    if packet.haslayer(ARP):
        return "ARP"

    return "Other"


# ──────────────────────────────────────────────────────────────────────────────
# Traffic categories  (single source of truth — no fallback duplication)
# ──────────────────────────────────────────────────────────────────────────────
TRAFFIC_CATEGORIES: dict[str, set[str]] = {
    "Browsing":       {"HTTP", "HTTPS", "HTTP-Proxy", "HTTPS-Alt", "QUIC"},
    "Email":          {"SMTP", "SMTPS", "IMAP", "IMAPS", "POP3", "POP3S"},
    "File Transfer":  {"FTP", "FTP-Data"},
    "Remote":         {"SSH", "Telnet", "RDP"},
    "DNS":            {"DNS", "DNS-over-TLS", "mDNS"},
    "VPN/Proxy":      {"OpenVPN", "PPTP", "SOCKS"},
    "Messaging":      {"XMPP", "XMPP-SSL", "Google-Push", "SIP", "SIPS"},
    "Database":       {"MySQL", "PostgreSQL", "MongoDB", "Redis"},
    "P2P":            {"BitTorrent"},
    "DHCP":           {"DHCP"},
}

# Pre-build reverse mapping for O(1) lookup
_PROTO_TO_CATEGORY: dict[str, str] = {
    proto: cat
    for cat, protos in TRAFFIC_CATEGORIES.items()
    for proto in protos
}

BROWSERS: set[str] = {
    "Google Chrome", "Safari", "Firefox", "Brave Browser", "Arc",
    "Microsoft Edge", "Google Chro", "Brave Brows", "Firefox CP",
    "WebKit", "com.apple.Safar",
}


def get_category(protocol_name: str) -> str:
    return _PROTO_TO_CATEGORY.get(protocol_name, "Other")


# ──────────────────────────────────────────────────────────────────────────────
# Known domain → service
# ──────────────────────────────────────────────────────────────────────────────
DOMAIN_SERVICES: dict[str, str] = {
    "google":     "Google",     "youtube":   "YouTube",
    "facebook":   "Facebook",   "instagram": "Instagram",
    "twitter":    "Twitter",    "x.com":     "X/Twitter",
    "whatsapp":   "WhatsApp",   "netflix":   "Netflix",
    "spotify":    "Spotify",    "apple":     "Apple",
    "icloud":     "iCloud",     "microsoft": "Microsoft",
    "outlook":    "Outlook",    "github":    "GitHub",
    "amazon":     "Amazon",     "aws":       "AWS",
    "cloudflare": "Cloudflare", "discord":   "Discord",
    "telegram":   "Telegram",   "zoom":      "Zoom",
    "slack":      "Slack",      "reddit":    "Reddit",
    "tiktok":     "TikTok",     "linkedin":  "LinkedIn",
    "gmail":      "Gmail",      "yahoo":     "Yahoo",
    "steam":      "Steam",      "twitch":    "Twitch",
}


def identify_service(domain: str | None) -> str | None:
    if not domain:
        return None
    dl = domain.lower()
    for key, svc in DOMAIN_SERVICES.items():
        if key in dl:
            return svc
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Process-map (port → app name)
# ──────────────────────────────────────────────────────────────────────────────
def update_process_map() -> None:
    """Poll the OS to map port numbers to process names."""
    new_cache: dict[tuple, str] = {}

    if os.name == "nt":          # Windows
        try:
            out = subprocess.check_output(
                ["netstat", "-ano"], stderr=subprocess.STDOUT
            ).decode(errors="replace")
            pids: dict[tuple, str] = {}
            for line in out.splitlines():
                parts = line.split()
                if len(parts) < 5:
                    continue
                proto     = parts[0]
                local_addr = parts[1]
                pid       = parts[-1]
                if ":" in local_addr:
                    port = local_addr.rsplit(":", 1)[-1]
                    pids[(port, proto)] = pid

            if pids:
                task_out = subprocess.check_output(
                    ["tasklist", "/NH", "/FO", "CSV"], stderr=subprocess.STDOUT
                ).decode(errors="replace")
                name_map: dict[str, str] = {}
                for line in task_out.splitlines():
                    p = line.replace('"', "").split(",")
                    if len(p) >= 2:
                        name_map[p[1]] = p[0]
                for (port, proto), pid in pids.items():
                    if pid in name_map:
                        new_cache[(port, proto)] = name_map[pid]
        except Exception:
            pass

    else:                         # macOS / Linux
        try:
            out = subprocess.check_output(
                ["lsof", "-i", "-n", "-P"], stderr=subprocess.STDOUT
            ).decode(errors="replace")
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) <= 8:
                    continue
                pid   = parts[1]
                port  = parts[8].rsplit(":", 1)[-1]
                proto = parts[7]
                try:
                    full = subprocess.check_output(
                        ["ps", "-p", pid, "-o", "comm="], stderr=subprocess.DEVNULL
                    ).decode(errors="replace").strip()
                    process = os.path.basename(full) if full else parts[0]
                except Exception:
                    process = parts[0]
                new_cache[(port, proto)] = process
        except Exception:
            pass

    # Single atomic dict swap — safe in CPython even without a lock
    # (dict assignment is a pointer swap at the C level)
    global process_cache
    process_cache = new_cache


def get_process_for_packet(packet) -> str:
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


# ──────────────────────────────────────────────────────────────────────────────
# DNS — thread-safe async reverse lookup
# ──────────────────────────────────────────────────────────────────────────────
def _dns_cache_set(ip: str, domain: str) -> None:
    """Insert into the LRU OrderedDict, evicting oldest entry if over cap."""
    with _lock:
        if ip in dns_cache:
            dns_cache.move_to_end(ip)
        dns_cache[ip] = domain
        if len(dns_cache) > MAX_DNS_CACHE:
            dns_cache.popitem(last=False)


def _resolve_dns_bg(ip: str) -> None:
    try:
        domain = socket.gethostbyaddr(ip)[0]
        _dns_cache_set(ip, domain)
    except Exception:
        _dns_cache_set(ip, ip)     # Cache negative result to avoid repeated lookups
    finally:
        with _dns_pending_lock:
            _dns_pending.discard(ip)


def get_domain(ip: str | None) -> str | None:
    if not ip:
        return None

    with _lock:
        cached = dns_cache.get(ip)
    if cached:
        return cached

    # Check-then-act is now guarded by _dns_pending_lock
    with _dns_pending_lock:
        if ip not in _dns_pending:
            _dns_pending.add(ip)
            dns_executor.submit(_resolve_dns_bg, ip)

    return ip   # Return IP immediately; domain resolves asynchronously


# ──────────────────────────────────────────────────────────────────────────────
# TLS SNI extraction (handshake header only — no decryption)
# ──────────────────────────────────────────────────────────────────────────────
def extract_tls_sni(payload: bytes) -> str | None:
    try:
        if len(payload) < 6:
            return None
        if payload[0] != 0x16:         # Not a TLS Handshake record
            return None
        if payload[5] != 0x01:         # Not a ClientHello
            return None

        # Skip: record header(5) + handshake_type(1) + length(3) + version(2) + random(32)
        offset = 5 + 1 + 3 + 2 + 32
        if offset + 1 >= len(payload):
            return None

        session_id_len = payload[offset]
        offset += 1 + session_id_len
        if offset + 2 >= len(payload):
            return None

        cipher_len = struct.unpack("!H", payload[offset:offset + 2])[0]
        offset += 2 + cipher_len
        if offset >= len(payload):
            return None

        comp_len = payload[offset]
        offset += 1 + comp_len
        if offset + 2 >= len(payload):
            return None

        ext_total_len = struct.unpack("!H", payload[offset:offset + 2])[0]
        offset += 2
        ext_end = offset + ext_total_len

        while offset + 4 < ext_end and offset + 4 < len(payload):
            ext_type = struct.unpack("!H", payload[offset:offset + 2])[0]
            ext_len  = struct.unpack("!H", payload[offset + 2:offset + 4])[0]
            offset  += 4
            if ext_type == 0x0000 and offset + 5 <= len(payload):   # SNI
                sni_name_len = struct.unpack("!H", payload[offset + 3:offset + 5])[0]
                raw = payload[offset + 5: offset + 5 + sni_name_len]
                return raw.decode("ascii", errors="ignore") or None
            offset += ext_len

    except Exception:
        pass
    return None


# ──────────────────────────────────────────────────────────────────────────────
# HTTP info extraction (plaintext only)
# ──────────────────────────────────────────────────────────────────────────────
def extract_http_info(payload_str: str) -> dict:
    info: dict = {}
    try:
        lines = payload_str.split("\r\n")
        if lines:
            m = re.match(
                r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT)\s+(\S+)\s+HTTP/",
                lines[0],
            )
            if m:
                info["method"] = m.group(1)
                info["path"]   = m.group(2)[:80]
            for line in lines[1:]:
                if line.lower().startswith("host:"):
                    info["host"] = line.split(":", 1)[1].strip()
                    break
    except Exception:
        pass
    return info


# ──────────────────────────────────────────────────────────────────────────────
# Sensitive-data detection (plaintext packets only)
# ──────────────────────────────────────────────────────────────────────────────
PATTERNS: dict[str, re.Pattern] = {
    "Credentials": re.compile(
        r'(password|passwd|pwd|secret|login|auth|session|token)'
        r'["\s:=]+([a-zA-Z0-9.\-_~]{6,})',
        re.I,
    ),
    "API Key":     re.compile(
        r'(?:AIza[0-9A-Za-z\-_]{35})|(?:sk-[a-zA-Z0-9]{20,})', re.I
    ),
    "Email Address": re.compile(
        r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
    ),
    "Credit Card": re.compile(r'\b(?:\d[ -]*?){13,16}\b'),
}

# Multicast ranges to ignore (RFC 5771)
_MULTICAST_PREFIXES = ("224.", "225.", "226.", "227.", "228.", "229.",
                       "230.", "231.", "232.", "233.", "234.", "235.",
                       "236.", "237.", "238.", "239.")


def luhn_check(card_number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", card_number)]
    if len(digits) < 13:
        return False
    total = 0
    for i, digit in enumerate(reversed(digits[:-1])):
        if i % 2 == 0:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return (total + digits[-1]) % 10 == 0


def mask_sensitive(content: str, label: str) -> str:
    if not content:
        return "[REDACTED]"
    s = str(content)
    if label == "Credit Card":
        digits = re.sub(r"\D", "", s)
        return f"****-****-****-{digits[-4:]}" if len(digits) >= 4 else "****"
    if label == "Email Address":
        parts = s.split("@")
        if len(parts) == 2:
            u = parts[0][0] + "***" + (parts[0][-1] if len(parts[0]) > 1 else "")
            d = parts[1][0] + "***" + parts[1][-3:] if len(parts[1]) > 3 else parts[1]
            return f"{u}@{d}"
        return s[:3] + "***"
    if label == "API Key":
        return (s[:4] + "****" + s[-4:]) if len(s) > 8 else "****"
    if label == "Credentials":
        return (s[:8] + "***[MASKED]") if len(s) > 8 else "***[MASKED]"
    return s[:6] + "***"


def inspect_payload(payload_str: str, packet_info: dict) -> None:
    dst_ip = packet_info.get("dst_ip", "")
    # Skip multicast / link-local noise
    if any(dst_ip.startswith(p) for p in _MULTICAST_PREFIXES):
        return

    for label, pattern in PATTERNS.items():
        for match in pattern.findall(payload_str):
            content = str(match[0] if isinstance(match, tuple) else match)

            if label == "Credit Card" and not luhn_check(content):
                continue

            masked    = mask_sensitive(content, label)
            is_crit   = label in ("Credit Card", "Credentials")
            severity  = "critical" if is_crit else "warning"
            is_ext    = not (
                dst_ip.startswith("192.168.")
                or dst_ip.startswith("10.")
                or dst_ip.startswith("172.16.")
                or dst_ip.startswith("127.")
            )
            assessment = "CRITICAL THREAT" if is_crit else ("THREAT" if is_ext else "INFO / FINE")

            add_alert(
                f"Leak Detected: {label}",
                severity,
                packet_info,
                f"{label} exposed to {dst_ip}\nPattern: {masked}\nAssessment: {assessment}",
                is_benign=not is_ext and not is_crit,
            )


# ──────────────────────────────────────────────────────────────────────────────
# Anomaly / flag detection
# ──────────────────────────────────────────────────────────────────────────────
def detect_anomalies(packet, packet_info: dict) -> None:
    if packet.haslayer(TCP):
        tcp   = packet[TCP]
        flags = int(tcp.flags)

        # Scapy flag bits: FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20

        if flags == 0:
            add_alert(
                "Security Flag: Null Scan", "critical", packet_info,
                "TCP packet with no flags set (reconnaissance)",
            )
        elif flags == (0x01 | 0x08 | 0x20):   # FIN + PSH + URG — Xmas scan
            add_alert(
                "Security Flag: Xmas Scan", "critical", packet_info,
                "TCP FIN+PSH+URG (reconnaissance)",
            )
        elif (flags & 0x01) and (flags & 0x02):  # FIN(0x01) + SYN(0x02)
            # ✓ Corrected: both SYN and FIN set simultaneously
            add_alert(
                "Security Flag: SYN-FIN", "critical", packet_info,
                "TCP SYN+FIN set simultaneously (firewall evasion attempt)",
            )
        elif flags & 0x04:                       # RST
            add_alert(
                "Network Flag: RST (Reset)", "warning", packet_info,
                f"Connection reset by {packet_info['src_ip']}. Could be a closed port.",
                is_benign=True,
            )
        elif flags & 0x20:                       # URG
            add_alert(
                "Network Flag: URG (Urgent)", "warning", packet_info,
                "Urgent pointer set — unusual in modern traffic.",
            )
        elif flags & 0x01:                       # FIN only
            add_alert(
                "Network Flag: FIN", "warning", packet_info,
                "Connection termination initiated.",
                is_benign=True,
            )
        elif (flags & 0x02) and not (flags & 0x10):   # SYN without ACK
            add_alert(
                "Network Flag: SYN", "warning", packet_info,
                f"New connection from {packet_info['src_ip']}.",
                is_benign=True,
            )

    if packet.haslayer(ICMP):
        icmp = packet[ICMP]
        if icmp.type == 5:
            add_alert(
                "Security Flag: ICMP Redirect", "critical", packet_info,
                "ICMP Redirect — possible MITM attempt.",
            )
        elif icmp.type == 8:
            add_alert(
                "Network Flag: Ping (Echo)", "warning", packet_info,
                f"ICMP Echo from {packet_info['src_ip']}.",
                is_benign=True,
            )

    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode(errors="ignore").upper()
            proto   = packet_info.get("protocol", "")
            if proto in ("SMTP", "POP3", "IMAP"):
                if "AUTH LOGIN" in payload or "USER " in payload or "PASS " in payload:
                    add_alert(
                        "Email Flag: Plaintext Auth", "critical", packet_info,
                        f"Plaintext authentication in {proto} traffic.",
                    )
        except Exception:
            pass


# ──────────────────────────────────────────────────────────────────────────────
# Web visit tracking
# ──────────────────────────────────────────────────────────────────────────────
def track_web_visit(packet, packet_info: dict) -> None:
    app_name = packet_info.get("app", "Unknown")
    protocol = packet_info.get("protocol", "")

    is_web_port     = protocol in ("HTTP", "HTTPS", "HTTP-Proxy", "HTTPS-Alt")
    is_quic_443     = (
        protocol == "UDP"
        and packet.haslayer(UDP)
        and packet[UDP].dport == 443
    )
    is_known_browser = any(b in app_name for b in BROWSERS)

    if not (is_known_browser or is_web_port or is_quic_443):
        return

    if app_name == "Unknown" and (is_web_port or is_quic_443):
        app_name = "Web Browser (Auto)"
        packet_info["app"] = app_name

    dst_ip = packet_info["dst_ip"]
    domain = packet_info.get("dst_domain") or dst_ip

    # Detect session start
    is_start = False
    if packet.haslayer(TCP):
        flags = int(packet[TCP].flags)
        if (flags & 0x02) and not (flags & 0x10):   # SYN without ACK
            is_start = True
    elif is_quic_443:
        with _lock:
            if (dst_ip, app_name) not in active_sessions:
                is_start = True

    if is_start:
        add_alert(
            "Site Visit Sensed", "warning", packet_info,
            f"{app_name} opening connection to {domain}. (SENSING START)",
            is_benign=True,
        )

    # Record visit once domain is known
    if domain and domain != dst_ip:
        session_key = (domain, app_name)
        with _lock:
            already = session_key in active_sessions
            if not already:
                # Evict oldest session if over cap
                if len(active_sessions) >= MAX_SESSIONS:
                    try:
                        active_sessions.pop(next(iter(active_sessions)))
                    except StopIteration:
                        pass
                active_sessions[session_key] = True

        if not already:
            add_alert(
                "Site Visit Recorded", "warning", packet_info,
                f"{app_name} connected to {domain}. (RECORDED)",
                is_benign=True,
            )


# ──────────────────────────────────────────────────────────────────────────────
# Alert helper
# ──────────────────────────────────────────────────────────────────────────────
def add_alert(
    alert_type: str,
    severity: str,
    packet_info: dict,
    content: str,
    *,
    is_benign: bool = False,
) -> None:
    """
    Thread-safe alert creation.

    is_benign: caller explicitly marks the event as non-threatening so we
               don't have to do fragile substring searches in content.
    """
    seriousness = "LOW" if is_benign else ("HIGH" if severity == "critical" else "MEDIUM")

    alert = {
        "id":         next(_alert_id_counter),   # atomic, no lock needed
        "time":       packet_info["time"],
        "type":       alert_type,
        "severity":   severity,
        "seriousness": seriousness,
        "is_threat":  not is_benign,
        "src":        packet_info["src_ip"],
        "dst":        packet_info["dst_ip"],
        "app":        packet_info.get("app", "Unknown"),
        "dst_domain": packet_info.get("dst_domain"),
        "content":    content,
        "protocol":   packet_info.get("protocol", ""),
        "category":   packet_info.get("category", "Other"),
    }

    with _lock:
        alerts.append(alert)
        if len(alerts) > MAX_ALERTS:
            alerts.pop(0)


# ──────────────────────────────────────────────────────────────────────────────
# Core packet processor
# ──────────────────────────────────────────────────────────────────────────────
def process_packet(packet) -> None:
    # ── ARP (no IP layer) ────────────────────────────────────────────────────
    if packet.haslayer(ARP):
        arp     = packet[ARP]
        pkt_sz  = len(packet)
        now_str = datetime.datetime.now().strftime("%H:%M:%S")

        packet_info = {
            "id":         None,   # filled in below under lock
            "time":       now_str,
            "src_ip":     arp.psrc,
            "dst_ip":     arp.pdst,
            "app":        "System",
            "src_domain": None,
            "dst_domain": None,
            "protocol":   "ARP",
            "flags":      None,
            "category":   "Network",
            "service":    None,
            "size":       pkt_sz,
            "info":       f"Who has {arp.pdst}?" if arp.op == 1
                          else f"{arp.psrc} is at {arp.hwsrc}",
        }

        detect_anomalies(packet, packet_info)

        with _lock:
            packet_info["id"] = len(packets_list) + 1
            packets_list.append(packet_info)
            if len(packets_list) > MAX_PACKETS:
                packets_list.pop(0)
            protocol_stats["ARP"]   += 1
            category_stats["Network"] += 1
            # noinspection PyGlobalUndefined
            globals()["total_bytes"] += pkt_sz

        return

    # ── IP / IPv6 ────────────────────────────────────────────────────────────
    if not packet.haslayer(IP) and not packet.haslayer(IPv6):
        return

    ip_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6]
    src_ip   = ip_layer.src
    dst_ip   = ip_layer.dst
    pkt_sz   = len(packet)
    now_str  = datetime.datetime.now().strftime("%H:%M:%S")

    protocol = identify_protocol(packet)
    category = get_category(protocol)

    # Process name (read from cache — no lock needed, dict swap is atomic)
    app_name = get_process_for_packet(packet)

    # Domain resolution (thread-safe internally)
    dst_domain = get_domain(dst_ip)
    src_domain = get_domain(src_ip)

    extra_info  = None
    sni_domain  = None

    # ── DNS ──────────────────────────────────────────────────────────────────
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        qname = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
        extra_info = f"Query: {qname}"

        if packet.haslayer(DNSRR):
            try:
                rdata = packet[DNSRR].rdata
                if isinstance(rdata, bytes):
                    rdata = rdata.decode(errors="ignore")
                if rdata:
                    _dns_cache_set(str(rdata), qname)
            except Exception:
                pass

        log_entry = {"time": now_str, "query": qname, "src": src_ip}
        with _lock:
            dns_query_log.append(log_entry)
            if len(dns_query_log) > MAX_DNS_LOG:
                dns_query_log.pop(0)

    # ── TLS SNI ──────────────────────────────────────────────────────────────
    if protocol in ("HTTPS", "HTTPS-Alt") and packet.haslayer(Raw):
        sni = extract_tls_sni(bytes(packet[Raw].load))
        if sni:
            sni_domain = sni
            if not dst_domain or dst_domain == dst_ip:
                dst_domain = sni
            _dns_cache_set(dst_ip, sni)
            extra_info = f"SNI: {sni}"

    # ── HTTP ─────────────────────────────────────────────────────────────────
    if protocol in ("HTTP", "HTTP-Proxy") and packet.haslayer(Raw):
        try:
            payload_str = packet[Raw].load.decode(errors="ignore")
            http_info   = extract_http_info(payload_str)
            if http_info.get("host"):
                dst_domain = http_info["host"]
                _dns_cache_set(dst_ip, http_info["host"])
            if http_info.get("method"):
                extra_info = f"{http_info['method']} {http_info.get('path', '')}"

            inspect_payload(payload_str, {
                "time":       now_str,
                "src_ip":     src_ip,
                "dst_ip":     dst_ip,
                "app":        app_name,
                "dst_domain": dst_domain,
                "protocol":   protocol,
                "category":   category,
            })
        except Exception:
            pass

    # ── SMTP / IMAP / POP3 ───────────────────────────────────────────────────
    if protocol in ("SMTP", "POP3", "IMAP") and packet.haslayer(Raw):
        try:
            payload_str = packet[Raw].load.decode(errors="ignore")
            inspect_payload(payload_str, {
                "time":       now_str,
                "src_ip":     src_ip,
                "dst_ip":     dst_ip,
                "app":        app_name,
                "dst_domain": dst_domain,
                "protocol":   protocol,
                "category":   category,
            })
            extra_info = f"Mail Data ({protocol})"
        except Exception:
            pass

    # ── Domain hits / service ────────────────────────────────────────────────
    if dst_domain:
        with _lock:
            domain_hits[dst_domain] += 1

    service   = identify_service(dst_domain) or identify_service(sni_domain)
    tcp_flags = str(packet[TCP].flags) if packet.haslayer(TCP) else None

    packet_info = {
        "id":         None,
        "time":       now_str,
        "src_ip":     src_ip,
        "dst_ip":     dst_ip,
        "app":        app_name,
        "src_domain": src_domain,
        "dst_domain": dst_domain,
        "protocol":   protocol,
        "flags":      tcp_flags,
        "category":   category,
        "service":    service,
        "size":       pkt_sz,
        "info":       extra_info,
    }

    detect_anomalies(packet, packet_info)
    track_web_visit(packet, packet_info)

    with _lock:
        packet_info["id"] = len(packets_list) + 1
        packets_list.append(packet_info)
        if len(packets_list) > MAX_PACKETS:
            packets_list.pop(0)
        protocol_stats[protocol]  += 1
        category_stats[category]  += 1
        app_bandwidth[app_name]   += pkt_sz
        connection_tracker[(src_ip, dst_ip, protocol)] = (
            connection_tracker.get((src_ip, dst_ip, protocol), 0) + 1
        )
        globals()["total_bytes"] += pkt_sz


# ──────────────────────────────────────────────────────────────────────────────
# Sniffer engine
# ──────────────────────────────────────────────────────────────────────────────
def _mapper_loop() -> None:
    while not stop_event.is_set():
        update_process_map()
        stop_event.wait(timeout=2)


def start_sniffer() -> None:
    global capture_start_time, sniffer_error

    print("⚡ Sniffer engine starting…")
    capture_start_time = datetime.datetime.now()
    stop_event.clear()

    threading.Thread(target=_mapper_loop, daemon=True, name="process-mapper").start()

    def should_stop(_pkt) -> bool:
        return stop_event.is_set()

    # Determine best interface — prefer en0 on macOS, fall back to scapy default
    if os.name == "nt":
        iface = None                             # Let Scapy pick on Windows
    else:
        iface = "en0" if os.path.exists("/sys/class/net/en0") else None
        if iface is None:
            # Use scapy's detected default
            try:
                iface = conf.iface or None
            except Exception:
                iface = None

    def _sniff_loop(iface_arg) -> None:
        while not stop_event.is_set():
            try:
                sniff(
                    iface=iface_arg,
                    prn=process_packet,
                    store=False,
                    timeout=1,
                    stop_filter=should_stop,
                )
            except Exception as exc:
                with _state_lock:
                    globals()["sniffer_error"] = str(exc)
                print(f"⚠️ Sniffer exception: {exc}")
                stop_event.wait(timeout=1)   # Brief pause before retry

    try:
        _sniff_loop(iface)
    except Exception as exc:
        print(f"❌ Fatal sniffer error on {iface}: {exc}. Retrying on default…")
        _sniff_loop(None)

    with _state_lock:
        globals()["sniffing"] = False


# ──────────────────────────────────────────────────────────────────────────────
# Auto-expiry daemon — uses datetime objects, not fragile string comparison
# ──────────────────────────────────────────────────────────────────────────────
def auto_expiry_loop() -> None:
    RETAIN_MINUTES = 10

    while True:
        time.sleep(120)
        cutoff = datetime.datetime.now() - datetime.timedelta(minutes=RETAIN_MINUTES)
        cutoff_str = cutoff.strftime("%H:%M:%S")

        with _lock:
            while packets_list:
                pkt_time_str = packets_list[0].get("time", "")
                if not pkt_time_str:
                    break
                try:
                    # Parse HH:MM:SS; combine with today's date for correct comparison
                    pkt_dt = datetime.datetime.combine(
                        datetime.date.today(),
                        datetime.time.fromisoformat(pkt_time_str),
                    )
                    if pkt_dt < cutoff:
                        packets_list.pop(0)
                    else:
                        break
                except ValueError:
                    break   # Unparseable time — leave the entry

            while dns_query_log:
                entry_time = dns_query_log[0].get("time", "")
                if not entry_time:
                    break
                try:
                    entry_dt = datetime.datetime.combine(
                        datetime.date.today(),
                        datetime.time.fromisoformat(entry_time),
                    )
                    if entry_dt < cutoff:
                        dns_query_log.pop(0)
                    else:
                        break
                except ValueError:
                    break


# ──────────────────────────────────────────────────────────────────────────────
# API Routes
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/api/start", methods=["POST"])
@require_auth
def start_capture():
    global sniffer_thread, total_bytes
    with _state_lock:
        if sniffing:
            return jsonify({"status": "already sniffing"})
        globals()["sniffing"] = True
        with _lock:
            globals()["total_bytes"] = 0
        stop_event.clear()
        t = threading.Thread(target=start_sniffer, daemon=True, name="sniffer")
        globals()["sniffer_thread"] = t
        t.start()
    return jsonify({"status": "sniffing started"})


@app.route("/api/stop", methods=["POST"])
@require_auth
def stop_capture():
    with _state_lock:
        globals()["sniffing"] = False
    stop_event.set()
    return jsonify({"status": "sniffing stopped"})


@app.route("/api/status", methods=["GET"])
@require_auth
def get_status():
    with _state_lock:
        _sniffing = sniffing
        _error    = sniffer_error

    uptime = None
    if capture_start_time and _sniffing:
        delta  = datetime.datetime.now() - capture_start_time
        uptime = str(delta).split(".")[0]

    with _lock:
        return jsonify({
            "sniffing":          _sniffing,
            "packet_count":      len(packets_list),
            "alert_count":       len(alerts),
            "total_bytes":       total_bytes,
            "unique_connections": len(connection_tracker),
            "unique_domains":    len({
                p.get("dst_domain") for p in packets_list if p.get("dst_domain")
            }),
            "uptime":            uptime,
            "error":             _error,
        })


@app.route("/api/packets", methods=["GET"])
@require_auth
def get_packets():
    count           = min(request.args.get("count", 50, type=int), 200)
    protocol_filter = request.args.get("protocol")
    category_filter = request.args.get("category")

    with _lock:
        result = list(packets_list)   # snapshot — never expose the live list

    if protocol_filter:
        result = [p for p in result if p.get("protocol") == protocol_filter]
    if category_filter:
        result = [p for p in result if p.get("category") == category_filter]

    return jsonify(result[-count:])


@app.route("/api/alerts", methods=["GET"])
@require_auth
def get_alerts():
    with _lock:
        return jsonify(list(alerts[-30:]))


@app.route("/api/stats", methods=["GET"])
@require_auth
def get_stats():
    with _lock:
        top_domains = sorted(domain_hits.items(),   key=lambda x: x[1], reverse=True)[:10]
        top_apps    = sorted(app_bandwidth.items(), key=lambda x: x[1], reverse=True)[:10]
        proto_dist  = dict(sorted(protocol_stats.items(), key=lambda x: x[1], reverse=True)[:15])
        cat_dist    = dict(sorted(category_stats.items(), key=lambda x: x[1], reverse=True))
        _total      = total_bytes

        return jsonify({
            "protocol_distribution": proto_dist,
            "category_distribution": cat_dist,
            "top_domains":   [{"domain": d, "count": c} for d, c in top_domains],
            "top_apps":      [{"app": a, "bytes": b} for a, b in top_apps],
            "total_bytes":   _total,
            "total_packets": len(packets_list),
            "unique_connections": len(connection_tracker),
        })


@app.route("/api/dns", methods=["GET"])
@require_auth
def get_dns_log():
    with _lock:
        return jsonify(list(dns_query_log[-50:]))


@app.route("/api/clear", methods=["POST"])
@require_auth
def clear_data():
    with _lock:
        packets_list.clear()
        alerts.clear()
        dns_query_log.clear()
        connection_tracker.clear()
        protocol_stats.clear()
        app_bandwidth.clear()
        domain_hits.clear()
        category_stats.clear()
        active_sessions.clear()
        globals()["total_bytes"] = 0
    return jsonify({"status": "cleared"})


@app.route("/api/token", methods=["GET"])
def get_token():
    if request.remote_addr not in ("127.0.0.1", "::1"):
        abort(403, description="Token only available from localhost")
    return jsonify({"token": API_TOKEN})


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    write_token()
    threading.Thread(target=auto_expiry_loop, daemon=True, name="auto-expiry").start()

    print(f"🛡️  Packet Sniffer API → http://127.0.0.1:8000")
    print(f"🔐 Auth token: {API_TOKEN[:8]}…")

    try:
        app.run(host="127.0.0.1", port=8000)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        with _state_lock:
            globals()["sniffing"] = False
        dns_executor.shutdown(wait=False, cancel_futures=True)
        print("\n🛑 Packet Sniffer stopped cleanly.")
