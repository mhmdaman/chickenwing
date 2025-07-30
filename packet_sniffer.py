from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
import datetime

def process_packet(packet):
    print("="*60)
    print(f"Time: {datetime.datetime.now()}")
    
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"[IP] {ip_layer.src} --> {ip_layer.dst}")

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"[TCP] Port: {tcp_layer.sport} --> {tcp_layer.dport}")
            
            if tcp_layer.dport == 80 or tcp_layer.sport == 80:
                print("[HTTP] Likely HTTP traffic")

        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"[UDP] Port: {udp_layer.sport} --> {udp_layer.dport}")

            if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
                dns = packet[DNS]
                print(f"[DNS] Query: {dns[DNSQR].qname.decode()}")

    else:
        print("[Unknown] Non-IP packet captured.")

print("Starting packet capture... Press Ctrl+C to stop.\n")
sniff(filter="ip", prn=process_packet, store=False)
