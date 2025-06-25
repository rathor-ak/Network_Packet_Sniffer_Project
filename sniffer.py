from scapy.all import sniff, IP, TCP
import sqlite3
import time
import logging
from collections import defaultdict

# Database setup
conn = sqlite3.connect('traffic.db')
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS packets (
    src_ip TEXT, dst_ip TEXT, sport INT, dport INT, length INT, timestamp TEXT
)''')
conn.commit()

# Logging setup
logging.basicConfig(filename='alert.log', level=logging.WARNING)

# Anomaly detection setup
ip_counter = defaultdict(int)
start_time = time.time()

def process_packet(packet):
    global start_time

    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        length = len(packet)
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')

        # Print
        print(f"{src_ip}:{sport} -> {dst_ip}:{dport} | Length: {length}")

        # Store in DB
        cursor.execute("INSERT INTO packets VALUES (?, ?, ?, ?, ?, ?)",
                       (src_ip, dst_ip, sport, dport, length, timestamp))
        conn.commit()

        # Detect anomaly
        ip_counter[src_ip] += 1
        if time.time() - start_time > 60:
            for ip, count in ip_counter.items():
                if count > 100:
                    print(f"[ALERT] Potential Flood from {ip}")
                    logging.warning(f"[ALERT] Potential Flood from {ip}")
            ip_counter.clear()
            start_time = time.time()

sniff(prn=process_packet, store=0)