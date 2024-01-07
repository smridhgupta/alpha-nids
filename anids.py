import os
import configparser
import logging
import queue
import smtplib
import threading
import subprocess
import time
from collections import defaultdict
from email.mime.text import MIMEText
import matplotlib.pyplot as plt
import scapy.all as scapy
from scapy.layers import http
from scapy.layers.inet import ICMP, TCP, UDP
from scapy.layers.dns import DNS

logging.basicConfig(filename='nids_log.log', level=logging.INFO, format='%(asctime)s [%(levelname)s] - %(message)s')

config = configparser.ConfigParser()
config.read('config.ini')


def get_config(section, key, fallback=None):
    try:
        return config.get(section, key)
    except (configparser.NoOptionError, configparser.NoSectionError):
        if fallback is not None:
            return fallback
        logging.error(f"Missing configuration for {section}:{key}")
        raise SystemExit(1)


THRESHOLD = int(get_config('General', 'Threshold'))
EMAIL_ALERTS = get_config('General', 'EmailAlerts').lower() == 'true'
WHITELIST = {x.strip() for x in get_config('Whitelist', 'Devices', '').split(',')}

arp_cache = {}
packet_count = defaultdict(int)
packet_queue = queue.Queue()


def packet_processing_thread():
    while True:
        packet = packet_queue.get()
        if packet is None:
            break
        packet_callback(packet)
        packet_queue.task_done()


def monitor_packet_rate():
    while True:
        time.sleep(1)
        for ip, count in packet_count.items():
            if count > THRESHOLD:
                alert_message = f"Potential Intrusion detected from IP {ip}!"
                logging.warning(alert_message)
                if EMAIL_ALERTS:
                    send_email("Potential Intrustion Detected", alert_message)
            packet_count[ip] = 0


def packet_sniffer():
    try:
        scapy.sniff(prn=packet_queue.put, store=0,
                    filter="ip or arp or icmp or udp or (tcp and (port 53 or port 443 or port 8443 or port 80))")
    except KeyboardInterrupt:
        packet_queue.put(None)
        

def visualize_data():
    plt.figure(figsize=(12, 10)) 

    while True:
        time.sleep(5)
        if packet_count:
            ips, counts = zip(*packet_count.items())
            plt.clf()  

            
            ax1 = plt.subplot(211)  

            ax1.bar(ips, counts, color='skyblue')
            ax1.set_title('Packet Counts per IP')
            ax1.set_xlabel('IP Address')
            ax1.set_ylabel('Packet Count')
            ax1.set_xticklabels(ips, rotation=45)

            
            ax2 = plt.subplot(212)  
            non_whitelisted = [ip for ip in arp_cache if arp_cache[ip] not in WHITELIST]
            if non_whitelisted:
                ax2.text(0.5, 0.5, '\n'.join(f"Non-whitelisted device: {ip}\nMAC: {arp_cache[ip]}" for ip in non_whitelisted),
                         ha='center', va='center', fontsize=10)
                ax2.set_title('Non-Whitelisted Devices')
                ax2.axis('off')  

            plt.tight_layout()
            plt.pause(0.01)


def send_email(subject, message):
    try:
        smtp_server = get_config('Email', 'SMTPServer')
        smtp_port = int(get_config('Email', 'SMTPPort'))
        username = os.environ.get('EMAIL_USERNAME') or get_config('Email', 'Username')
        password = os.environ.get('EMAIL_PASSWORD') or get_config('Email', 'Password')
        recipient = get_config('Email', 'To')
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(username, password)
            msg = MIMEText(message)
            msg['Subject'] = subject
            msg['From'] = username
            msg['To'] = recipient
            server.send_message(msg)
    except Exception as e:
        logging.error(f"Error sending email: {e}")


def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        packet_count[src_ip] += 1
        if packet.haslayer(http.HTTPRequest):
            process_http(packet)
        elif packet.haslayer(ICMP):
            process_icmp(packet)
        elif packet.haslayer(DNS) and packet[DNS].qr == 0:
            process_dns(packet)
    elif packet.haslayer(scapy.ARP):
        process_arp(packet)


alerted_devices = set() 


def process_arp(packet):
    src_ip = packet[scapy.ARP].psrc
    src_mac = packet[scapy.ARP].hwsrc
    if src_ip not in arp_cache:
        logging.info(f"New device detected: IP {src_ip}, MAC {src_mac}")
        arp_cache[src_ip] = src_mac  # Add the new device to the ARP cache
    elif arp_cache[src_ip] != src_mac:
        alert_message = f"ARP table change detected: IP {src_ip}, MAC {src_mac}. Previous MAC was {arp_cache[src_ip]}"
        logging.warning(alert_message)
        send_email("ARP Table Change Detected", alert_message)
        arp_cache[src_ip] = src_mac  # Update the ARP cache with the new MAC address

    if src_mac not in WHITELIST and src_mac not in alerted_devices:
        alert_message = f"WARNING: Device with MAC {src_mac} is not whitelisted!"
        logging.warning(alert_message)
        send_email("Unauthorized Device Detected", alert_message)
        alerted_devices.add(src_mac)  # Add the alerted MAC to the set


def process_http(packet):
    host = packet[http.HTTPRequest].Host.decode('utf-8') if packet[http.HTTPRequest].Host else "Unknown"
    uri = packet[http.HTTPRequest].Path.decode('utf-8') if packet[http.HTTPRequest].Path else "/"
    src_mac = packet[scapy.Ether].src
    if "malicious_string" in host or "malicious_string" in uri:
        logging.warning(f"Malicious request detected to {host}{uri}")
    if src_mac not in WHITELIST:
        alert_message = f"WARNING: Non-whitelisted device with MAC {src_mac} is sending HTTP requests!"
        logging.warning(alert_message)
        send_email("Unauthorized HTTP Request Detected", alert_message)


def process_icmp(packet):
    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst
    message = f"ICMP packet detected: {src_ip} -> {dst_ip}."
    logging.info(message)


def process_dns(packet):
    if packet.haslayer(DNS) and packet[DNS].qr == 0:  # Only process DNS queries
        src_ip = packet[scapy.IP].src
        query = packet[DNS].qd.qname.decode('utf-8')
        message = f"DNS Query detected from {src_ip}: {query}"
        logging.info(message)


def add_to_whitelist(mac_address):
    global WHITELIST
    WHITELIST.add(mac_address)
    config.set('Whitelist', 'Devices', ','.join(WHITELIST))
    with open('config.ini', 'w') as configfile:
        config.write(configfile)


def remove_from_whitelist(mac_address):
    global WHITELIST
    WHITELIST.discard(mac_address)
    config.set('Whitelist', 'Devices', ','.join(WHITELIST))
    with open('config.ini', 'w') as configfile:
        config.write(configfile)

    try:
        subprocess.run(['iptables', '-A', 'INPUT', '-m', 'mac', '--mac-source', mac_address, ' j', 'DROP'], check=True)
        logging.info(f"Device with MAC {mac_address} has been removed from the whitelist and blocked.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to block device: {e}")

packet_processing_thread_instance = threading.Thread(target=packet_processing_thread, daemon=True)
packet_processing_thread_instance.start()

monitor_packet_rate_thread = threading.Thread(target=monitor_packet_rate, daemon=True)
monitor_packet_rate_thread.start()

visualization_thread = threading.Thread(target=visualize_data, daemon=True)

if __name__ == "__main__":
    print("Starting Network Intrusion Detection System...")
    try:
        packet_processing_thread_instance = threading.Thread(target=packet_processing_thread)
        monitor_packet_rate_thread = threading.Thread(target=monitor_packet_rate)
        visualization_thread = threading.Thread(target=visualize_data)
        packet_sniffer_thread = threading.Thread(target=packet_sniffer)

        packet_processing_thread_instance.start()
        monitor_packet_rate_thread.start()
        visualization_thread.start()
        packet_sniffer_thread.start()

        packet_processing_thread_instance.join()
        monitor_packet_rate_thread.join()
        visualization_thread.join()
        packet_sniffer_thread.join()

        print("Exiting...")
    except KeyboardInterrupt:
        packet_queue.put(None)
        print("Exiting...")
