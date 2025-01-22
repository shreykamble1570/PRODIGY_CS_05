from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = "Unknown"

        if TCP in packet:
            protocol = "TCP"
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            payload = bytes(packet[TCP].payload)
        elif UDP in packet:
            protocol = "UDP"
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport
            payload = bytes(packet[UDP].payload)

        print(f"IP {ip_src}:{tcp_sport if protocol == 'TCP' else udp_sport} -> {ip_dst}:{tcp_dport if protocol == 'TCP' else udp_dport} ({protocol})")
        print(f"Payload: {payload}\n")

def main():
    print("Starting network packet analyzer...")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
