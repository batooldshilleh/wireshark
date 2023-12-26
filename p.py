from scapy.all import *

def process_packet(packet):
    if IP in packet or IPv6 in packet:
        print(f"Packet: {packet.summary()}")
        print(f"IP Source: {packet[IP].src}")
        print(f"IP Destination: {packet[IP].dst}")
        print(f"MAC Source: {packet.src}")
        print(f"MAC Destination: {packet.dst}")
        
        if packet.haslayer(TCP):
            print(f"Source Port: {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")
            print(f"Payload: {packet[TCP].payload}")
        
        elif packet.haslayer(UDP):
            print(f"Source Port: {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")
            print(f"Payload: {packet[UDP].payload}")

        print("=====")


file_path = '/home/batool/Documents/GitHub/wireshark/bbbb.pcapng'
packets = rdpcap(file_path)

for packet in packets:
    process_packet(packet)

