
from scapy.all import sniff, IP, TCP
import sqlite3
from datetime import datetime
from collections import defaultdict
import time

# Database setup
conn = sqlite3.connect('traffic.db')
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS packets (
    src_ip TEXT,
    dst_ip TEXT,
    sport INTEGER,
    dport INTEGER,
    length INTEGER,
    timestamp TEXT
)
''')
conn.commit()

# Alert log file
alert_file = open("alert.log", "a")

# Track IP packet count for flooding detection
ip_packet_counter = defaultdict(list)

# Set threshold
THRESHOLD = 20  # number of packets
TIME_WINDOW = 5  # seconds

def log_alert(message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    alert_msg = f"[{timestamp}] ALERT: {message}\n"
    print(alert_msg)
    alert_file.write(alert_msg)
    alert_file.flush()

def process_packet(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        length = len(packet)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Save packet to DB
        cursor.execute("INSERT INTO packets VALUES (?, ?, ?, ?, ?, ?)",
                       (src_ip, dst_ip, sport, dport, length, timestamp))
        conn.commit()

        print(f"{src_ip}:{sport} -> {dst_ip}:{dport} | Len: {length}")

        # Track IP activity
        now = time.time()
        ip_packet_counter[src_ip] = [t for t in ip_packet_counter[src_ip] if now - t < TIME_WINDOW]
        ip_packet_counter[src_ip].append(now)

        # Detect potential flood
        if len(ip_packet_counter[src_ip]) > THRESHOLD:
            log_alert(f"Potential flood detected from {src_ip} ({len(ip_packet_counter[src_ip])} packets in {TIME_WINDOW}s)")

print("Sniffing started... Press Ctrl+C to stop.")
try:
    sniff(prn=process_packet, store=0)
except KeyboardInterrupt:
    print("Sniffing stopped.")
    alert_file.close()
    conn.close()
