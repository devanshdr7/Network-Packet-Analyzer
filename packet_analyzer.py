from scapy.all import sniff, IP, TCP, UDP, Raw, conf
from datetime import datetime

def analyze_packet(packet):
    print("=" * 60)
    print(f"Timestamp: {datetime.now()}")

    if IP in packet:
        ip_layer = packet[IP]
        print(f"[IP] Source: {ip_layer.src} --> Destination: {ip_layer.dst}")
        
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"[TCP] Source Port: {tcp_layer.sport} --> Destination Port: {tcp_layer.dport}")
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"[UDP] Source Port: {udp_layer.sport} --> Destination Port: {udp_layer.dport}")
        else:
            print("[Other Protocol] Non-TCP/UDP protocol detected.")

        if Raw in packet:
            payload = packet[Raw].load
            print(f"[Payload] Raw Data:\n{payload[:100]}")  # First 100 bytes only
        else:
            print("[Payload] No raw data.")
    else:
        print("[Info] Non-IP packet captured.")

# Configure to use L3 socket
conf.L3socket = conf.L3socket

# Start sniffing
print("Starting network packet analyzer... (Press Ctrl+C to stop)\n")
sniff(prn=analyze_packet, store=0)
