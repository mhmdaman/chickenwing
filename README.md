# 🛡️ Chickenwing

**Chickenwing** is a professional-grade background network monitoring and privacy protection tool for macOS & Windows. It combines the powerful packet-capturing capabilities of **Python & Scapy** with a high-end **Electron & React** dashboard to provide real-time visibility into your system's data traffic.

## 🌟 Core Features

*   **Real-Time Data Capture**: Monitor every TCP, UDP, and DNS packet flowing in and out of your Mac.
*   **Application-Level Attribution**: See exactly which app (Chrome, Slack, Mail, etc.) is responsible for each network connection.
*   **Privacy Shield**: Intelligent scanning of packet payloads to detect unencrypted sensitive data:
    *   **Credentials**: Detects plaintext passwords, session tokens, and auth headers.
    *   **Financial Data**: Scans for valid Credit Card numbers using the mathematical Luhn Algorithm.
    *   **Personal Info**: Flags exposed email addresses and API keys (e.g., OpenAI, AWS).
*   **Dynamic Domain Resolution**: Automatically resolves destination IP addresses into human-readable domain names.
*   **Background Monitoring**: Runs persistently in the background, allowing you to minimize the window while it keeps a watchful eye on your traffic.
*   **High-End Dashboard**: A modern, sleek UI featuring real-time data tables, security alert feeds, and live performance metrics.
*   **Traffic Search & Filtering**: Instantly search your live traffic logs by IP, Protocol, or Application name.

---

## 🛠 How It Works (The Architecture)

The application operates as a **two-tier system**:

### 1. The Engine (Python Backend)
The backend, located in `backend/packet.py`, is the "brain" of the operation.
*   **Packet Sniffing**: Uses the `Scapy` library to hook into your network interface. It captures every packet (TCP, UDP, DNS) passing through your system.
*   **Application Identification (Process Mapping)**: This is a key feature. It periodically runs `lsof -i -n -P` to map active network ports to their corresponding macOS process names (e.g., "Chrome", "Spotify"). When a packet is captured, the backend looks up its port to tell you which app sent it.
*   **Sensitive Data Detection**:
    *   **Regex Engine**: Scans the raw payload of every packet for patterns matching emails, API keys (like AWS or OpenAI), and credentials.
    *   **Luhn Algorithm**: For credit cards, it doesn't just look for numbers; it runs the mathematical Luhn check to ensure the card number is valid and not just random data noise.
*   **DNS Resolution**: It performs reverse DNS lookups on every IP address to turn `142.250.190.46` into `google.com`. It used a local cache to keep this fast.
*   **Lightweight API**: Uses `Flask` to serve all this data to the frontend in real-time.

### 2. The Dashboard (Electron + React)
The frontend provides a "Pro" visual experience using modern web technologies.
*   **Electron Shell**: Provides the desktop window and handles the lifecycle of the Python process. When you close the app, it cleanly kills the background sniffer.
*   **Vite + React**: The UI is built for performance. It uses a **Polling Mechanism** (every 1.5s) to fetch the latest snapshots from the backend.
*   **Design System**: Implements a custom "Apple-style" dark mode with glassmorphism, using `Framer Motion` for smooth interface transitions and `Lucide` for crisp telemetry icons.

---

## 🚦 Getting Started

### Prerequisites
*   **Node.js & npm**
*   **Python 3.12+**
*   **Python Libraries**: `pip install scapy flask flask-cors`

### 1. Fix macOS Permissions (CRITICAL)
By default, macOS restricts access to the network interface (`/dev/bpf`). You must run this command once to allow the sniffer to work without root:
```bash
sudo chmod 644 /dev/bpf*
```

### 2. Launch the Application
```bash
npm start
```
*This single command launches the Vite server, waits for it to be ready, and then starts the Electron app.*

---

## 📂 Project Structure

```text
├── backend/
│   └── packet.py     # The Python Sniffing Engine
├── src/
│   ├── App.jsx       # The Dashboard logic and UI
│   ├── main.jsx      # React Entry point
│   └── index.css     # The Design System & Styling
├── main.js           # Electron Main Process (Lifecycle management)
├── package.json      # Dependencies and Startup scripts
└── icon.png          # Custom generated Pro icon
```

---

## 🛡 Security & Privacy
*   **Local Only**: The Flask backend is bound to `127.0.0.1`. It does not expose your data to the local network or the internet.
*   **Passive Sniffing**: This tool only listens to traffic; it does not inject packets or modify your network behavior.
*   **Data Retention**: Captured packets are stored in a small memory-based "rolling window" of 100 items. Closing the app wipes all captured data.

---

## 💡 Troubleshooting

*   **"Permission Denied"**: Run the `sudo chmod 644 /dev/bpf*` command mentioned above.
*   **Backend Connection Refused**: Ensure no other process is using port `8000` (Flask) or `5173` (Vite).
*   **Unknown App**: If an application name shows as "Unknown", it's likely a very short-lived connection that closed before the process mapper could identify it.

---

*Evolve your network security with Chickenwing.*
