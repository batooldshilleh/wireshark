from scapy.all import *
from tabulate import tabulate

def extract_packet_info(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        # Extracting Ethernet frame information
        eth_src = packet[Ether].src
        eth_dst = packet[Ether].dst

        # Extracting lengths
        header_length = packet[IP].ihl * 32  # Header length in bytes
        payload_length = len(packet[Raw].load) if Raw in packet else 0  # Payload length in bytes

        # Calculating packet and frame sizes
        packet_size = len(packet)
        frame_size = len(packet.build())

        data = [
            ["IP Source", ip_src],
            ["IP Destination", ip_dst],
            ["Source Port", src_port],
            ["Destination Port", dst_port],
            ["Ethernet Source MAC", eth_src],
            ["Ethernet Destination MAC", eth_dst],
            ["Header Length", f"{header_length} bytes"],
            ["Payload Length", f"{payload_length} bytes"],
            ["Packet Size", f"{packet_size} bytes"],
            ["Frame Size", f"{frame_size} bytes"]
        ]

        print(tabulate(data, headers=["Field", "Value"], tablefmt="fancy_grid"))
        print("=====")


file_path = '/home/batool/Documents/GitHub/wireshark/bbb.pcapng'
packets = rdpcap(file_path)

for packet in packets:
    extract_packet_info(packet)

