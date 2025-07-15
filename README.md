# NetFlow: Network Monitoring & Spoofing Tool

## 🌐 Overview

NetFlow is a Python-based network tool designed to help you understand and interact with network traffic. It offers both passive monitoring capabilities and active Man-in-the-Middle (MITM) functionalities like DNS spoofing and DNS traffic monitoring.

**Please read this entire README carefully, especially the safety and ethical use sections, before running the tool.**

## ✨ Features

This tool provides the following key functionalities:

1.  **DNS Spoofing (Active MITM):**
    * Redirects network traffic for specified domains to IP addresses of your choice.
    * Acts as a "fake phone book" for the internet.
    * Requires ARP Spoofing to put your machine in the middle.

2.  **Passive HTTP/HTTPS Hostname & URL Logging:**
    * Monitors and logs HTTP (regular web pages) and HTTPS (secure web pages) hostnames and URLs.
    * Purely passive – only observes traffic passing through your own machine.
    * **Cannot decrypt HTTPS content** (due to encryption).

3.  **DNS Traffic Monitor (Active MITM):**
    * Monitors and logs all DNS (Domain Name System) requests from targeted devices.
    * Shows which websites (domains) victims are trying to visit and their real resolved IP addresses.
    * Requires ARP Spoofing to capture traffic from other devices.

## ⚠️ Important Safety & Ethical Use Warnings

* **USE ONLY ON NETWORKS YOU OWN OR HAVE EXPLICIT PERMISSION TO TEST.** Using this tool on public Wi-Fi, school/work networks, or any network without permission is **illegal and unethical**.
* **UNDERSTAND THE RISKS:** MITM attacks can disrupt network services and may violate privacy.
* **HTTPS (Secure Websites):** This tool *cannot* decrypt HTTPS traffic. Browsers will show security warnings if you try to spoof HTTPS sites. This is a security feature, not a bug, and protects users.
* **Antivirus/Firewall:** Your antivirus software or firewall might flag this tool as suspicious because it uses techniques (like ARP spoofing) that are also used by malicious software. You might need to temporarily disable them for testing (at your own risk).

## 📋 Prerequisites

Before you can run the tool, you need to set up your environment:

1.  **Python 3:** Make sure you have Python 3 installed on your system.
    * You can check by opening a terminal/command prompt and typing: `python3 --version`
    * If you don't have it, download it from [python.org](https://www.python.org/downloads/).

2.  **Required Python Libraries:**
    * `scapy`: A powerful packet manipulation program.
    * `netifaces`: Used to get network interface information.
    * `colorama`: Used for colorful console output.

3.  **Administrator/Root Privileges:**
    * Network operations like ARP spoofing and raw packet sniffing require special permissions. You will need to run the script with `sudo` on Linux/macOS or as an Administrator on Windows.

## ⚙️ Installation & Setup

Follow these steps to get the tool ready on your machine:

1.  **Download the Tool:**
    * Download or clone this project to your computer.
    * Unzip the folder if necessary.

2.  **Open Terminal/Command Prompt:**
    * **Linux/macOS:** Open your Terminal application.
    * **Windows:** Search for "Command Prompt" or "PowerShell", right-click, and select "Run as administrator".

3.  **Navigate to the Tool's Directory:**
    * Use the `cd` command to go into the folder where you saved the tool's files.
        * Example (Linux/macOS): `cd /path/to/your/netflow-tool`
        * Example (Windows): `cd C:\Users\YourUser\Documents\NetFlow-Tool`

4.  **Install Required Libraries:**
    * It's a good practice to create a `requirements.txt` file in your project directory with the following content:
        ```
        scapy
        netifaces
        colorama
        ```
    * Then, install them using pip:
        * **Linux/macOS:** `sudo pip3 install -r requirements.txt`
        * **Windows:** `pip install -r requirements.txt` (if using Command Prompt as Admin)

## 🚀 How to Use the Tool

### **General Steps to Start the Tool:**

1.  **Open your Terminal/Command Prompt** (as Administrator/root).
2.  **Navigate** to the tool's directory (as shown in Installation Step 3).
3.  **Run the script:**
    * **Linux/macOS:** `sudo python3 your_script_name.py` (Replace `your_script_name.py` with the actual file name of your main tool script, e.g., `netflow_tool.py`)
    * **Windows:** `python your_script_name.py`
4.  The tool will then list **available network interfaces**.
    * Choose the **number** corresponding to your active network connection (e.g., `wlan0` for Wi-Fi, `eth0` for wired).
5.  You will then see the **Main Menu**.

### **Mode 1: DNS Spoofing (Active MITM)**

This mode is for redirecting a victim's web requests to an IP address of your choice.

1.  **From the Main Menu, enter `1`** and press Enter.
2.  The tool will ask: `Enter domains to spoof (format: domain:ip,domain2:ip2):`
    * **Example:** If you want to redirect `example.com` to your machine's IP (e.g., `192.168.1.100`), type: `example.com:192.168.1.100`
    * Press Enter.
3.  The tool will then ask for domains to highlight (optional). You can leave this blank or enter the domain(s) you just spoofed (e.g., `example.com`). Press Enter.
4.  The tool will begin ARP spoofing and sniffing.
5.  **On the Victim Device (another device on your network):**
    * **Crucially, clear its DNS cache first!**
        * **Windows:** `ipconfig /flushdns` in Command Prompt (Admin).
        * **macOS:** `sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder` in Terminal.
        * **Phones/Tablets:** Toggle Wi-Fi off/on or restart.
    * Open a web browser and try to visit the spoofed domain (e.g., `http://example.com`). Use `http` initially to avoid certificate warnings.
    * You can also test with `nslookup example.com` in the victim's terminal/cmd.
6.  **Verify it worked:**
    * **On your tool's console:** Look for a message like `[+] Spoofing DNS response for example.com -> 192.168.1.100 (Victim: [Victim's IP])`
    * **On the victim's `nslookup` output:** It should show the **fake IP** (`192.168.1.100`) as the resolved address, not the real one.
    * **On the victim's browser:** If `192.168.1.100` is running a web server, you should see that server's page.

### **Mode 2: Passive HTTP/HTTPS Hostname & URL Logging**

This mode monitors *your own* computer's web activity.

1.  **From the Main Menu, enter `2`** and press Enter.
2.  The tool will start listening.
3.  **On the SAME computer running the tool:**
    * Open your web browser.
    * Visit various websites (e.g., `https://www.google.com`, `https://www.youtube.com`, or any `http://` site if you know one).
4.  **Verify it worked:**
    * **On your tool's console:** You should see lines like `[HTTPS Host] From [your_ip]: www.google.com` or `[HTTP URL] From [your_ip]: http://example.com/some/path`.
    * **In the logs/ directory:** After stopping the tool, check `general_http_https_traffic.log`.

### **Mode 3: DNS Traffic Monitor (Active MITM)**

This mode logs all DNS requests from targeted victims on your network.

1.  **From the Main Menu, enter `3`** and press Enter.
2.  The tool will ask for domains to highlight (optional). Enter domains you want to specifically watch for (e.g., `facebook.com,twitter.com`). Press Enter.
3.  The tool will begin ARP spoofing and sniffing for DNS traffic.
4.  **On the Victim Device (another device on your network):**
    * Simply use the internet normally. Browse websites, use apps that connect online.
5.  **Verify it worked:**
    * **On your tool's console:** You should see lines like `[DNS Visit] Victim: [Victim_IP] requested: google.com -> resolved to: [Real_IP]` (with colors and bolding for highlighted domains).
    * **In the logs/ directory:** After stopping the tool, check `all_dns_traffic_summary.log` and `victim_dns_traffic_[VICTIM_IP].log` for detailed logs.

### **Stopping the Tool (All Modes):**

* To stop the tool and restore network settings, simply press `Ctrl+C` in the terminal where the tool is running.

## 🐞 Troubleshooting Common Issues

* **`Permission denied` or `Operation not permitted`:**
    * **Cause:** You didn't run the script with enough privileges.
    * **Solution:** Rerun the script using `sudo` on Linux/macOS (e.g., `sudo python3 your_script.py`) or as Administrator on Windows.

* **`ModuleNotFoundError: No module named 'scapy'` (or `netifaces`, `colorama`):**
    * **Cause:** You haven't installed all the required Python libraries.
    * **Solution:** Go back to the "Installation & Setup" section and make sure you ran `pip install -r requirements.txt` successfully.

* **`WARNING: Socket ... failed with 'name 'victim_ip' is not defined'. It was closed.` (Mode 3):**
    * **Cause:** This usually means some print/logging code tried to use the `victim_ip` variable before it was assigned a value for a particular type of network packet.
    * **Solution:** Ensure your `dns_traffic_monitor_packet_handler` function correctly nests the print and logging statements. Make sure they are inside the `if pkt.haslayer(DNS) ...` block and relevant `for` loops so that `victim_ip` and other related variables are always defined when used. (Refer to the specific code fix provided in previous discussions if you got this error after copying snippets).

* **"DNS Spoofing / DNS Traffic Monitor (Mode 1 & 3) isn't redirecting/seeing traffic from other devices":**
    * **Cause 1: ARP Spoofing Failed:** Your tool isn't successfully becoming the Man-in-the-Middle.
        * **Check:** On the victim, run `arp -a` (Windows) or `ip neigh` (Linux/macOS). The MAC address next to your network gateway's IP (e.g., `192.168.1.1`) should now be your attacker machine's MAC address. If not, ARP spoofing is the problem.
        * **Solution:** Ensure your tool's console shows `[*] Starting ARP spoofing thread...` without errors. Check for active firewalls on your attacker machine that might block ARP responses.
    * **Cause 2: DNS Resolution not to Spoofed IP:** The victim is not getting the fake DNS answer.
        * **Check:** On the victim, run `nslookup [your_test_domain]` (for spoofing) or simply browse for DNS monitoring. Does `nslookup` show the fake IP (for spoofing)?
        * **Solution:** Ensure you flushed the victim's DNS cache. There might be a race condition where the real DNS server's response beats your spoofed one (less common but possible).
    * **Cause 3: Traffic Not Forwarding (for DNS Spoofing to local Apache):** The victim correctly resolves the domain to your IP, but your web server page doesn't load.
        * **Check:** Is your Apache server running and accessible directly by its IP on the victim? (You confirmed this previously, which is good).
        * **Solution:** Ensure your tool's `forward_packet` function is correctly set up to allow traffic destined *for your own machine's IP* to pass through to your local services, rather than trying to forward it out to the gateway. Also, check any firewall on your attacker machine that might block incoming connections to your Apache server (e.g., `sudo ufw disable` temporarily on Linux, or allow port 80).

* **"Passive HTTP/HTTPS logging (Mode 2) isn't showing traffic from other devices":**
    * **Cause:** This is normal on modern switched networks. Your computer primarily sees traffic sent to/from itself.
    * **Solution:** This mode is designed for *your own* machine's traffic. To see other devices' HTTP/HTTPS traffic, you would need to use an active MITM mode (like DNS Spoofing) or be on a network using a hub (very rare).

## 📄 License

This project is licensed under the MIT License - see the `LICENSE` file (if provided) for details.

## 📞 Contact

If you have questions or need further assistance, feel free to reach out.
