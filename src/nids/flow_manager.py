import time
import threading
from scapy.layers import inet
from src.core.event_bus import bus
from src.core.logger import system_logger

class Flow:
    def __init__(self, src_ip, src_port, dst_ip, dst_port, protocol):
        self.flow_id = (src_ip, src_port, dst_ip, dst_port, protocol)
        self.packets = []
        self.timestamps = []
        self.start_time = time.time()
        self.last_active = self.start_time
        
    def add_packet(self, packet):
        self.packets.append(packet)
        # Use packet's internal time if available (useful for PCAP replay)
        arrival_time = float(packet.time) if hasattr(packet, 'time') else time.time()
        self.timestamps.append(arrival_time)
        self.last_active = time.time()

class FlowManager:
    def __init__(self, timeout=60):
        self.active_flows = {}
        self.timeout = timeout
        self.is_running = True
        
        # Subscribe to new packet events from the sniffer
        bus.subscribe("new_packet", self.handle_packet)
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()

    def handle_packet(self, packet):
        if not packet.haslayer(inet.IP):
            return

        ip_layer = packet[inet.IP]
        protocol = ip_layer.proto
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        src_port = 0
        dst_port = 0
        
        if packet.haslayer(inet.TCP):
            src_port = packet[inet.TCP].sport
            dst_port = packet[inet.TCP].dport
        elif packet.haslayer(inet.UDP):
            src_port = packet[inet.UDP].sport
            dst_port = packet[inet.UDP].dport

        # Flow ID is bidirectional (canonical tuple)
        flow_id = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)])) + (protocol,)

        if flow_id not in self.active_flows:
            self.active_flows[flow_id] = Flow(src_ip, src_port, dst_ip, dst_port, protocol)
            system_logger.debug(f"New flow tracked: {flow_id}")
        
        self.active_flows[flow_id].add_packet(packet)
        
        # Check if flow should be sent to ML engine (e.g., reached packet threshold)
        if len(self.active_flows[flow_id].packets) >= 100: # Increased threshold for efficiency
            self.process_flow(flow_id)

    def process_flow(self, flow_id):
        if flow_id in self.active_flows:
            flow = self.active_flows.pop(flow_id)
            # Emit flow event for the ML engine
            bus.emit("analyze_flow", flow)
            system_logger.debug(f"Flow {flow_id} sent for AI analysis (Threshold reached).")

    def _cleanup_loop(self):
        """Periodically scans for and processes expired flows."""
        while self.is_running:
            time.sleep(30)
            self.cleanup_expired_flows()

    def cleanup_expired_flows(self):
        current_time = time.time()
        expired_ids = []
        
        for flow_id, flow in self.active_flows.items():
            if current_time - flow.last_active > self.timeout:
                expired_ids.append(flow_id)
        
        for flow_id in expired_ids:
            flow = self.active_flows.pop(flow_id)
            bus.emit("analyze_flow", flow)
            system_logger.info(f"Flow {flow_id} expired and sent for analysis.")

    def stop(self):
        self.is_running = False
