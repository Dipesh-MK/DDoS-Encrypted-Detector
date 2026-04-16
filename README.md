# 🛡️ Encrypted DDoS Detector Platform

> **Network Security Project** • Developed to intelligently detect and mitigate advanced encrypted DDoS attacks (L4/L7) without violating payload privacy.

![Dashboard Preview](ddos-web-ui/src/assets/hero.png) *(Note: Ensure hero image is present or update path)*

## 📖 Introduction
Traditional firewalls often fail to stop modern DDoS vectors—especially **encrypted attacks (TLS/SSL)**—because Deep Packet Inspection (DPI) cannot read the contents of the payload. 

This project aims to solve this critical vulnerability by utilizing a **Machine Learning (Random Forest) Engine** that analyzes the *cadence* and flow behavior (packet timing, variance, speed) of network traffic rather than the encrypted contents themselves. By using flow metrics, it can flag malicious zero-day anomalies accurately while maintaining strict end-to-end user privacy.

### Key Features
- **L4/L7 Attack Detection:** Catches Volumetric TLS Floods, Slowloris, SYN Floods, HTTP GET Floods, and ICMP botnets.
- **Privacy-Preserving (Encrypted):** Inspects timing metrics (Inter-Arrival Time, PPS, Bytes) without breaking TLS encryption.
- **Dual-Node Simulation Environment:** Comes with an integrated React dashboard where one device can act as the "Detector" while a second device visually launches configurable attacks across the network.
- **Real-Time Explainability:** Not only flags attacks but strictly details *why* the ML model flagged them (e.g., "abnormally high packets-per-second overwhelming decrypt stack").

---

## 🛠️ Architecture & Tech Stack

- **ML Detection Engine:** Python, Scikit-learn (Random Forest Hybrid model trained on CIC-IDS2019 + custom PCAP data).
- **Backend Scanner & State Sync:** Flask API (Python) for triggering live network scans via Windows Native ARP execution.
- **Frontend Dashboard:** React.js, Vite, TailwindCSS (for real-time heartbeat monitoring and threat visualization).
- **Extensibility Tunneling:** Ngrok (for mobile/secondary device access during live multi-node simulations).

---

## 🚀 How to Run the Project (Live Simulation)

You need **two devices** to simulate the local network attack scenario fully (e.g., a laptop and a phone/second laptop). 

### 1. Start the Backend API (Detector Machine)
This must be run on the machine that intends to "detect" the attacks.
```bash
# Navigate to the project root
cd DDoS-Encrypted-Detector

# Run the backend Flask scanner and state API
python scan_api.py
```
*Wait until you see the `[Scanner] Network Scanner API starting...` output, running on Port `8001`.*

### 2. Start the Frontend Dashboard
Open a **new terminal tab** and start the React Web UI:
```bash
cd ddos-web-ui
npm install   # If running for the very first time
npm run dev
```
*The local UI will spin up on `http://localhost:5173`. Open this on the Detector machine.*

### 3. Expose the Network (For Attacker Machine)
Open a **third terminal tab** and run Ngrok to tunnel the application to the internet so your second device can access it.
```bash
ngrok http --url=YOUR-NGROK-URL.ngrok-free.app 5173
```
*Replace `YOUR-NGROK-URL` with your static Ngrok domain (e.g., `gentle-emu...`).*

### 4. Run the Attack Simulation
1. **On your Laptop (Detector):** Open `http://localhost:5173`. Click **"Run as Detector"** → **"Start Sensor"**. The radar will start mapping background traffic.
2. **On your Second Device (Attacker):** Open the Ngrok URL. Click **"Run as Attacker"**.
3. Click **"Scan Local Network"** on the attacker device. It will do a massive 254-host ping sweep.
4. Select your laptop's IP from the discovered list.
5. Choose an attack vector (e.g., *TLS Flood*) and click **"Launch Attack"**.
6. **Watch the Detector UI:** Your laptop's dashboard heartbeat will instantly spike red, log an `[ALERT]`, and generate an explainability card showing the exact ML metrics that flagged the attack.

---

## 🧩 How to Test Pre-recorded Traffic (PCAP)
Don't want to run a live simulation? The platform also analyzes pre-recorded network environments.
1. Open the UI to the **PCAP Testing** tab.
2. Make sure you select the **Server-side Captures**.
3. Pick `ddos_tls_flood_server.pcap` and click **"Run PCAP Test"**.
4. The dashboard will simulate how the ML model stripped the packet flow and identified the malicious intent in an isolated environment.

---
*Created for our comprehensive academic Network Security evaluation.*
