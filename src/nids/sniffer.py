import scapy.all as scapy
from scapy.layers import inet
from src.core.event_bus import bus
from src.core.logger import system_logger

class NIDSSniffer:
    def __init__(self, interface=None, pcap_file=None):
        self.interface = interface
        self.pcap_file = pcap_file

    def packet_callback(self, packet):
        if packet.haslayer(inet.IP):
            # Emit raw packet event for flow aggregation
            bus.emit("new_packet", packet)

    def start(self):
        if self.pcap_file:
            system_logger.info(f"[*] Analyzing offline PCAP: {self.pcap_file}")
            try:
                scapy.sniff(offline=self.pcap_file, store=False, prn=self.packet_callback)
                system_logger.info("[+] PCAP analysis complete.")
            except Exception as e:
                system_logger.error(f"Failed to read PCAP: {e}")
        else:
            if self.interface:
                system_logger.info(f"[*] Starting NIDS sniffer on {self.interface}...")
            else:
                system_logger.info("[*] Starting NIDS sniffer on default interface...")
                
            try:
                scapy.sniff(iface=self.interface, store=False, prn=self.packet_callback)
            except Exception as e:
                system_logger.error(f"Failed to start sniffer: {e}")

if __name__ == "__main__":
    sniffer = NIDSSniffer("eth0")
    sniffer.start()
