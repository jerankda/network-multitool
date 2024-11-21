import os
import socket
import subprocess
import dns.resolver
import ipaddress
import time
from scapy.all import sniff
from datetime import datetime
from cryptography.fernet import Fernet
import hashlib
from PIL import Image

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
    print("                 \033[94mNetworking & Hacking CLI Tool v2.0\033[0m")
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
    print("12. Port Scanner")
    print("13. Hash Cracking")
    print("14. File Steganography")
    print("15. Password Generator")
    print("16. Vulnerability Checker")
    print("17. Packet Sniffer")
    print("18. Encrypt/Decrypt Tool")
    print("19. Brute Force Simulation")
    print("0. Exit")
    choice = input("\033[92mEnter your choice: \033[0m")
    return choice

# Core Networking Features
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

def port_scanner(ip):
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        465: "SMTPS",
        587: "SMTP (Alternate)",
        853: "DNS over TLS",
        993: "IMAPS",
        995: "POP3S"
    }
    print(f"\033[93mScanning ports on {ip}...\033[0m")
    for port in range(1, 65536):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                service = common_ports.get(port, "Unknown Service")
                if port in common_ports:
                    # Highlight relevant ports
                    print(f"\033[92mPort {port} is open ({service})\033[0m")
                else:
                    print(f"Port {port} is open ({service})")

def hash_cracking(hash_value, wordlist):
    try:
        with open(wordlist, 'r') as file:
            for line in file:
                hashed = hashlib.md5(line.strip().encode()).hexdigest()
                if hashed == hash_value:
                    print(f"Hash cracked! Original value: {line.strip()}")
                    return
        print("Hash not found in wordlist.")
    except FileNotFoundError:
        print("Wordlist not found.")

def file_steganography(img_path, message=None, output_path=None):
    if message and output_path:
        img = Image.open(img_path)
        img = img.convert("RGB")
        pixels = img.load()
        binary_message = ''.join(format(ord(c), '08b') for c in message) + '11111111'
        idx = 0
        for i in range(img.size[0]):
            for j in range(img.size[1]):
                r, g, b = pixels[i, j]
                if idx < len(binary_message):
                    r = int(bin(r)[:-1] + binary_message[idx], 2)
                    idx += 1
                pixels[i, j] = (r, g, b)
        img.save(output_path)
        print(f"Message hidden in {output_path}")
    else:
        img = Image.open(img_path)
        pixels = img.load()
        binary_message = ""
        for i in range(img.size[0]):
            for j in range(img.size[1]):
                r, g, b = pixels[i, j]
                binary_message += bin(r)[-1]
        message = ''.join(chr(int(binary_message[i:i+8], 2)) for i in range(0, len(binary_message), 8))
        print(f"Hidden message: {message.strip(chr(255))}")

def password_generator(length=12):
    import random
    import string
    chars = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(chars) for _ in range(length))
    print(f"Generated Password: {password}")

def vulnerability_checker(url):
    try:
        import requests
        payloads = ["' OR '1'='1", "' AND 1=1--", "'; DROP TABLE users;--"]
        vulnerable = False
        print(f"Testing {url} for SQL Injection vulnerabilities...")
        for payload in payloads:
            response = requests.post(url, data={"input": payload})
            if "error" not in response.text.lower():
                print(f"Potential SQL Injection vulnerability detected with payload: {payload}")
                vulnerable = True
        if vulnerable:
            print("\033[91mThe website is likely vulnerable to SQL Injection attacks.\033[0m")
        else:
            print("\033[92mNo SQL Injection vulnerabilities detected.\033[0m")
    except Exception as e:
        print(f"Error: {e}")

def encrypt_decrypt_tool(mode, key=None, input_text=None):
    if mode == "encrypt":
        key = Fernet.generate_key()
        cipher = Fernet(key)
        encrypted = cipher.encrypt(input_text.encode())
        print(f"Key: {key.decode()}")
        print(f"Encrypted Text: {encrypted.decode()}")
    elif mode == "decrypt":
        cipher = Fernet(key)
        decrypted = cipher.decrypt(input_text.encode())
        print(f"Decrypted Text: {decrypted.decode()}")

def brute_force_simulation(target, wordlist):
    try:
        with open(wordlist, 'r') as file:
            for line in file:
                print(f"Trying: {line.strip()}")
                time.sleep(0.5)  # Simulate brute force
    except FileNotFoundError:
        print("Wordlist not found.")

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
        elif choice == "12":
            ip = input("Enter IP to scan: ")
            port_scanner(ip)
        elif choice == "13":
            hash_value = input("Enter hash to crack: ")
            wordlist = input("Enter path to wordlist: ")
            hash_cracking(hash_value, wordlist)
        elif choice == "14":
            mode = input("Hide (h) or Extract (e) message from an image? ")
            if mode.lower() == "h":
                img_path = input("Enter path to image: ")
                message = input("Enter message to hide: ")
                output_path = input("Enter path to save new image: ")
                file_steganography(img_path, message, output_path)
            elif mode.lower() == "e":
                img_path = input("Enter path to image: ")
                file_steganography(img_path)
        elif choice == "15":
            length = int(input("Enter desired password length: "))
            password_generator(length)
        elif choice == "16":
            url = input("Enter URL to check for vulnerabilities: ")
            vulnerability_checker(url)
        elif choice == "17":
            interface = input("Enter network interface (e.g., eth0): ")
            packet_capture(interface)
        elif choice == "18":
            mode = input("Encrypt (e) or Decrypt (d)? ")
            if mode.lower() == "e":
                input_text = input("Enter text to encrypt: ")
                encrypt_decrypt_tool("encrypt", input_text=input_text)
            elif mode.lower() == "d":
                key = input("Enter decryption key: ").encode()
                input_text = input("Enter encrypted text: ")
                encrypt_decrypt_tool("decrypt", key=key, input_text=input_text)
        elif choice == "19":
            target = input("Enter target (e.g., SSH username@host): ")
            wordlist = input("Enter path to wordlist: ")
            brute_force_simulation(target, wordlist)
        elif choice == "0":
            print("\033[92mExiting Brekzware. Goodbye!\033[0m")
            break
        else:
            print("\033[91mInvalid choice. Try again.\033[0m")