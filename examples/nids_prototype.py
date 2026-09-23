import scapy.all as scapy
from scapy.layers import inet

def packet_callback(packet):
    if packet.haslayer(inet.IP):
        ip_src = packet[inet.IP].src
        ip_dst = packet[inet.IP].dst
        print(f"Packet: {ip_src} -> {ip_dst}")

def start_sniffing(interface):
    print(f"[*] Starting sniffer on {interface}...")
    scapy.sniff(iface=interface, store=False, prn=packet_callback)

if __name__ == "__main__":
    # Note: Requires root privileges to sniff packets
    # Replace 'eth0' with your actual interface
    start_sniffing("eth0")
