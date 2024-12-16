from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source: {ip_layer.src} -> Destination: {ip_layer.dst}")
        if TCP in packet:
            print(f"  TCP Packet: {packet[TCP].sport} -> {packet[TCP].dport}")
        elif UDP in packet:
            print(f"  UDP Packet: {packet[UDP].sport} -> {packet[UDP].dport}")

# Start sniffing on the desired interface (replace 'eth0' with your network interface)
print("Starting the packet sniffer...")
sniff(prn=packet_callback, store=False)




