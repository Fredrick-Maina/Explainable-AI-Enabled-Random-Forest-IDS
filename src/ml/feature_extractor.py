import numpy as np
from scapy.layers import inet

class FeatureExtractor:
    """
    Extracts features from a Flow object for ML inference.
    Maps to CIC-IDS2017 feature set with IAT and Protocol parsing.
    """
    def extract(self, flow):
        packets = flow.packets
        timestamps = flow.timestamps
        if not packets:
            return None

        # 1. Flow Basic Features
        flow_duration = (timestamps[-1] - timestamps[0]) * 1e6 # Microseconds
        total_fwd_packets = 0
        total_bwd_packets = 0
        total_fwd_bytes = 0
        total_bwd_bytes = 0

        fwd_lengths = []
        bwd_lengths = []
        fwd_timestamps = []
        bwd_timestamps = []

        src_ip = flow.flow_id[0] if isinstance(flow.flow_id[0], str) else flow.flow_id[0][0]

        for i, p in enumerate(packets):
            if not p.haslayer(inet.IP):
                continue

            p_len = len(p)
            p_time = timestamps[i]

            if p[inet.IP].src == src_ip:
                total_fwd_packets += 1
                total_fwd_bytes += p_len
                fwd_lengths.append(p_len)
                fwd_timestamps.append(p_time)
            else:
                total_bwd_packets += 1
                total_bwd_bytes += p_len
                bwd_lengths.append(p_len)
                bwd_timestamps.append(p_time)

        # 2. IAT Features (Inter-Arrival Time)
        def calc_iat(ts_list):
            if len(ts_list) < 2:
                return [0, 0, 0, 0] # Mean, Max, Min, Std
            iats = np.diff(ts_list) * 1e6 # To Microseconds
            return [np.mean(iats), np.max(iats), np.min(iats), np.std(iats)]

        flow_iat = calc_iat(timestamps)
        fwd_iat = calc_iat(fwd_timestamps)
        bwd_iat = calc_iat(bwd_timestamps)

        # 3. Protocol Specific (DPI Lite)
        is_dns = 1 if any(p.haslayer("DNS") for p in packets) else 0
        is_http = 1 if any(p.haslayer("HTTP") for p in packets) else 0

        # 4. Packet Length Features
        all_lengths = fwd_lengths + bwd_lengths
        max_len = max(all_lengths) if all_lengths else 0
        min_len = min(all_lengths) if all_lengths else 0
        mean_len = np.mean(all_lengths) if all_lengths else 0
        std_len = np.std(all_lengths) if all_lengths else 0

        # 5. Flag Features
        flags = {'fin': 0, 'syn': 0, 'rst': 0, 'psh': 0, 'ack': 0, 'urg': 0}
        for p in packets:
            if p.haslayer(inet.TCP):
                f = p[inet.TCP].flags
                if f & 0x01: flags['fin'] += 1
                if f & 0x02: flags['syn'] += 1
                if f & 0x04: flags['rst'] += 1
                if f & 0x08: flags['psh'] += 1
                if f & 0x10: flags['ack'] += 1
                if f & 0x20: flags['urg'] += 1

        # Construct feature vector
        feature_vector = [
            flow_duration, total_fwd_packets, total_bwd_packets, total_fwd_bytes, total_bwd_bytes,
            max_len, min_len, mean_len, std_len,
            *flow_iat, *fwd_iat, *bwd_iat,
            flags['fin'], flags['syn'], flags['rst'], flags['psh'], flags['ack'], flags['urg'],
            is_dns, is_http
        ]

        # Pad to 78 features
        feature_vector += [0] * (78 - len(feature_vector))

        return np.array(feature_vector).reshape(1, -1)
