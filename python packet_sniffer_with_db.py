from scapy.all import sniff, IP, TCP
import sqlite3
from datetime import datetime

# Connect to SQLite database (creates if not exists)
conn = sqlite3.connect('traffic.db')
cursor = conn.cursor()

# Create table to store packet data
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

# Define packet processing function
def process_packet(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        length = len(packet)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Insert into database
        cursor.execute("INSERT INTO packets VALUES (?, ?, ?, ?, ?, ?)",
                       (src_ip, dst_ip, sport, dport, length, timestamp))
        conn.commit()

        # Print output
        print(f"{src_ip}:{sport} -> {dst_ip}:{dport} | Length: {length} | Time: {timestamp}")

# Start sniffing (root/admin permission required)
print("Sniffing started... Press Ctrl+C to stop.")
sniff(prn=process_packet, store=0)
