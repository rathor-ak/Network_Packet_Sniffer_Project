Network Packet Sniffer with Alert System

INSTRUCTIONS:

1. Install dependencies:
   pip install scapy matplotlib

2. Run sniffer (in terminal):
   python sniffer.py
   - Captures packets, logs headers, detects anomalies, and stores to SQLite.

3. To view graph of traffic:
   python plot_graph.py

4. Alert log will be saved in 'alert.log' file.

FILES:
- sniffer.py      : Main sniffer and detection logic
- plot_graph.py   : Graph generation using matplotlib
- traffic.db      : SQLite DB auto-created
- alert.log       : Auto-generated on anomaly