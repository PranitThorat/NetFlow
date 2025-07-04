# 👻💀 NetFlow - Network Traffic Analyzer & DNS Spoofing Tool 💀👻

[![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/)
[![Scapy Version](https://img.shields.io/badge/scapy-2.x-green.svg)](https://scapy.net/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub Stars](https://img.shields.io/github/stars/PranitThorat/NetFlow?style=social)](https://github.com/PranitThorat/NetFlow/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/PranitThorat/NetFlow?style=social)](https://github.com/PranitThorat/NetFlow/network/members)

## 🌟 Introduction

NetFlow is a powerful Python-based network analysis and penetration testing tool designed to monitor network traffic, identify active hosts, and perform DNS spoofing attacks. It offers both passive monitoring capabilities for HTTP/HTTPS and DNS traffic, as well as an active DNS MITM (Man-in-the-Middle) mode.

This tool is ideal for network administrators, security researchers, and enthusiasts looking to understand network communication, detect suspicious activity, or simulate DNS-based attacks in a controlled environment.

## ✨ Features

* **Network Scanning:** Discover live hosts on the local network using ARP ping. 📡
* **ARP Spoofing:** Perform ARP poisoning to intercept traffic between targets and the gateway. 🔗
* **DNS Spoofing (MITM):** Redirect DNS queries for specified domains to an attacker-controlled IP. 🕸️
* **Passive HTTP/HTTPS Monitoring:** Log visited HTTP URLs and hostnames (including SNI for HTTPS). 🌐
* **Passive DNS Traffic Analysis:** Log all DNS resolutions by victim IPs, with victim-specific log files and a comprehensive A-Z sorted summary. 🔍
* **Real-time Output:** Colored console output for easy readability and highlighting of specific domains. 🌈
* **Logging:** All captured and manipulated data is meticulously logged to a `logs/` directory for post-analysis. 📁
* **Graceful Shutdown:** Proper cleanup and ARP table restoration on Ctrl+C. ✅

## 🛠️ Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/PranitThorat/NetFlow.git
    cd NetFlow
    ```

2.  **Install dependencies:**
    NetFlow requires `scapy` and `netifaces`. It's highly recommended to use a virtual environment.

    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows: .\venv\Scripts\activate
    pip install scapy netifaces
    ```

3.  **Permissions:**
    Running network sniffing and ARP spoofing tools usually requires root/administrator privileges.

    * **Linux:**
        ```bash
        sudo python3 netflow.py
        ```
    * **Windows:** Run your command prompt or PowerShell as Administrator.

## 🚀 Usage

```bash
python3 netflow.py
