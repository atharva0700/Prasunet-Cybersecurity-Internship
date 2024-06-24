from scapy.all import sniff, IP, TCP, UDP, ICMP


def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        print(f"\nPacket: {packet.summary()}")
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        
        if protocol == 6:  # TCP protocol
            if TCP in packet:
                print("Protocol : TCP")
                print(f"Source Port : {packet[TCP].sport}")
                print(f"Destination Port : {packet[TCP].dport}")
        elif protocol == 17:  # UDP protocol
            if UDP in packet:
                print("Protocol : UDP")
                print(f"Source Port : {packet[UDP].sport}")
                print(f"Destination Port : {packet[UDP].dport}")
        elif protocol == 1:  # ICMP protocol
            if ICMP in packet:
                print("Protocol : ICMP")
        else:
            print("Protocol : Other")

# Start sniffing
print("\n Starting packet capture ")
sniff(prn=packet_callback, count=10)
print("\n Packet capture completed \n")
