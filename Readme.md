# Network Packet Analyzer

A simple **GUI-based network packet sniffer** built using **Python, Scapy, Tkinter, and Matplotlib**. This tool captures network traffic and provides insights through a graphical interface.

---
## 🚀 Features
- **Live Packet Capture**: Sniffs network traffic in real-time
- **Protocol Filtering**: View only TCP, UDP, or all packets
- **Graphical Dashboard**: Displays packet statistics in a live-updating chart
- **User-Friendly GUI**: Built with Tkinter for easy use

---
## 📦 Installation
### 1️⃣ **Install Python (If Not Installed)**
Download and install Python from [Python.org](https://www.python.org/downloads/).
Ensure to check **"Add Python to PATH"** during installation.

### 2️⃣ **Clone This Repository**
```sh
git clone https://github.com/Jikku345/PRODIGY_CS_05.git
cd network-sniffer-gui
```

### 3️⃣ **Install Dependencies**
```sh
pip install scapy matplotlib tk
```

### 4️⃣ **Enable WinPcap (Windows Only)**
Scapy requires **WinPcap or Npcap** to capture packets on Windows.
Download and install [Npcap](https://nmap.org/npcap/).

---
## 🛠 Usage
Run the script using:
```sh
python pacscn.py
```
### 🎯 How to Use:
1. Select a protocol filter (TCP, UDP, or All).
2. Click **Start Sniffing** to begin capturing packets.
3. View live network traffic in the text area.
4. Click **Show Graph** to visualize packet distribution.
5. Click **Stop Sniffing** to stop capturing.

---
## ⚠ Troubleshooting
### ❌ "python: command not found"
Ensure Python is installed and added to the system PATH. Verify by running:
```sh
python --version
```

### ❌ "No module named 'scapy'"
Ensure dependencies are installed:
```sh
pip install scapy
```

### ❌ "RuntimeError: WinPcap is not installed"
Install **Npcap** from [Npcap official site](https://nmap.org/npcap/).

---
## 📜 License
This project is licensed under the MIT License.

---
## 🤝 Contributing
Feel free to submit pull requests or issues on GitHub!

---
## 👨‍💻 Author
Developed by **Jikku Abraham** 🚀

