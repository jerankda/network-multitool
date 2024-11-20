import os
import socket
import subprocess
import dns.resolver
import ipaddress
import time
from scapy.all import sniff
from datetime import datetime


# edgy banner for memes
def display_banner():
    print("\033[92m")
    print(r"""
 ▄▄▄▄    ██▀███  ▓█████  ██ ▄█▀▒███████▒ █     █░ ▄▄▄       ██▀███  ▓█████ 
▓█████▄ ▓██ ▒ ██▒▓█   ▀  ██▄█▒ ▒ ▒ ▒ ▄▀░▓█░ █ ░█░▒████▄    ▓██ ▒ ██▒▓█   ▀ 
▒██▒ ▄██▓██ ░▄█ ▒▒███   ▓███▄░ ░ ▒ ▄▀▒░ ▒█░ █ ░█ ▒██  ▀█▄  ▓██ ░▄█ ▒▒███   
▒██░█▀  ▒██▀▀█▄  ▒▓█  ▄ ▓██ █▄   ▄▀▒   ░░█░ █ ░█ ░██▄▄▄▄██ ▒██▀▀█▄  ▒▓█  ▄ 
░▓█  ▀█▓░██▓ ▒██▒░▒████▒▒██▒ █▄▒███████▒░░██▒██▓  ▓█   ▓██▒░██▓ ▒██▒░▒████▒
░▒▓███▀▒░ ▒▓ ░▒▓░░░ ▒░ ░▒ ▒▒ ▓▒░▒▒ ▓░▒░▒░ ▓░▒ ▒   ▒▒   ▓▒█░░ ▒▓ ░▒▓░░░ ▒░ ░
▒░▒   ░   ░▒ ░ ▒░ ░ ░  ░░ ░▒ ▒░░░▒ ▒ ░ ▒  ▒ ░ ░    ▒   ▒▒ ░  ░▒ ░ ▒░ ░ ░  ░
 ░    ░   ░░   ░    ░   ░ ░░ ░ ░ ░ ░ ░ ░  ░   ░    ░   ▒     ░░   ░    ░   
 ░         ░        ░  ░░  ░     ░ ░        ░          ░  ░   ░        ░  ░
      ░                        ░                                           
    """)
    print("                         \033[91mB R E K Z W A R E\033[0m")
    print("                      \033[94mNetworking CLI Tool v1.0\033[0m")
    print("\033[0m")

#ui/ux demon
def display_menu():
    print("\033[93mChoose an option:\033[0m")
    print("1. Ping an IP/Domain")
    print("2. Perform Traceroute")
    print("3. DNS Lookup")
    print("4. Reverse DNS Lookup")
    print("5. WHOIS Query")
    print("6. HTTP Response Check")
    print("7. Perform Ping Sweep")
    print("8. Network Interface Info")
    print("9. Packet Capture")
    print("10. IP Calculator")
    print("11. Ping Monitor")
    print("0. Exit")
    choice = input("\033[92mEnter your choice: \033[0m")
    return choice

# functions #skid
def ping_ip(ip, count=4):
    subprocess.run(["ping", "-c", str(count), ip])

def traceroute(domain):
    subprocess.run(["traceroute", domain])

def dns_lookup(domain):
    resolver = dns.resolver.Resolver()
    answers = resolver.resolve(domain)
    for answer in answers:
        print(answer)

def reverse_dns(ip):
    try:
        host = socket.gethostbyaddr(ip)
        print(f"Host: {host[0]}")
    except Exception as e:
        print(f"Error: {e}")

def whois_query(domain):
    try:
        import whois
        w = whois.whois(domain)
        print(w)
    except Exception as e:
        print(f"Error: {e}")

def http_response_check(url):
    try:
        import requests
        response = requests.get(url)
        print(f"Status Code: {response.status_code}")
        print(f"Headers: {response.headers}")
    except Exception as e:
        print(f"Error: {e}")

def ping_sweep(network):
    try:
        for ip in ipaddress.IPv4Network(network, strict=False):
            response = os.system(f"ping -c 1 -w 1 {ip} > /dev/null 2>&1")
            if response == 0:
                print(f"{ip} is up!")
    except Exception as e:
        print(f"Error: {e}")

def network_info():
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    print(f"Hostname: {hostname}")
    print(f"IP Address: {ip}")

def packet_capture(interface):
    print("Capturing packets (requires sudo)...")
    sniff(iface=interface, count=10, prn=lambda x: x.summary())

def ip_calculator(ip, cidr):
    network = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False)
    print(f"Network: {network.network_address}")
    print(f"Broadcast: {network.broadcast_address}")
    print(f"Netmask: {network.netmask}")
    print(f"Hosts: {[str(host) for host in network.hosts()]}")

def ping_monitor(ip, interval=5):
    print(f"Monitoring ping for {ip} (Ctrl+C to stop)")
    try:
        while True:
            subprocess.run(["ping", "-c", "1", ip])
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")

# Main
if __name__ == "__main__":
    display_banner()
    while True:
        choice = display_menu()
        if choice == "1":
            ip = input("Enter IP/Domain: ")
            ping_ip(ip)
        elif choice == "2":
            domain = input("Enter Domain: ")
            traceroute(domain)
        elif choice == "3":
            domain = input("Enter Domain: ")
            dns_lookup(domain)
        elif choice == "4":
            ip = input("Enter IP: ")
            reverse_dns(ip)
        elif choice == "5":
            domain = input("Enter Domain: ")
            whois_query(domain)
        elif choice == "6":
            url = input("Enter URL: ")
            http_response_check(url)
        elif choice == "7":
            network = input("Enter Network (e.g., 192.168.1.0/24): ")
            ping_sweep(network)
        elif choice == "8":
            network_info()
        elif choice == "9":
            interface = input("Enter Interface (e.g., eth0): ")
            packet_capture(interface)
        elif choice == "10":
            ip = input("Enter IP: ")
            cidr = input("Enter CIDR (e.g., 24): ")
            ip_calculator(ip, cidr)
        elif choice == "11":
            ip = input("Enter IP/Domain: ")
            ping_monitor(ip)
        elif choice == "0":
            print("\033[92mExiting Brekzware. Goodbye!\033[0m")
            break
        else:
            print("\033[91mInvalid choice. Try again.\033[0m")