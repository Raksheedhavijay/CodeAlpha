import logging
from scapy.all import sniff, IP, TCP, UDP

# Configure logging
logging.basicConfig(
    filename="packet_log.txt",      
    filemode="w",                    
    format="%(asctime)s - %(message)s",
    level=logging.INFO
)

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        # Map protocol numbers
        if proto == 6:
            protocol = "TCP"
        elif proto == 17:
            protocol = "UDP"
        else:
            protocol = str(proto)

        log_entry = f"Source: {src_ip} --> Destination: {dst_ip} | Protocol: {protocol}"

        # Add port info if TCP/UDP
        if packet.haslayer(TCP):
            log_entry += f" | Src Port: {packet[TCP].sport}, Dst Port: {packet[TCP].dport}"
            payload = bytes(packet[TCP].payload)
        elif packet.haslayer(UDP):
            log_entry += f" | Src Port: {packet[UDP].sport}, Dst Port: {packet[UDP].dport}"
            payload = bytes(packet[UDP].payload)
        else:
            payload = b""

        # Add payload snippet
        if payload:
            log_entry += f" | Payload: {payload[:50]}..."

        # Write to log file
        logging.info(log_entry)

        # Also print to console
        print(log_entry)

print("Starting detailed packet capture... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=False)
