
from scapy.all import sniff, IP, TCP, UDP


def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        print(f"\nSource IP: {ip_src} → Destination IP: {ip_dst} | Protocol: {proto}")

        if TCP in packet:
            print(f"TCP Ports: {packet[TCP].sport} → {packet[TCP].dport}")
        elif UDP in packet:
            print(f"UDP Ports: {packet[UDP].sport} → {packet[UDP].dport}")


sniff(prn=packet_callback, count=20)
