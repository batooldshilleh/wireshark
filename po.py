from scapy.all import *

def extract_credentials(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode('utf-8', errors='ignore')

           
            if 'POST /userinfo.php' in payload:
                print(f"IP Source: {ip_src}")
                print(f"IP Destination: {ip_dst}")
                print(f"Source Port: {src_port}")
                print(f"Destination Port: {dst_port}")
                print(f"payload:{payload}")

               

               
                if 'uname=' in payload:
                    username = payload.split('uname=')[1].split('&')[0]  #user&pass

                if 'pass=' in payload:
                    password = payload.split('pass=')[1].split('&')[0]

                print(f"Username: {username}")
                print(f"Password: {password}")
                print("=====")


file_path = '/home/batool/Documents/GitHub/wireshark/bb.pcapng'
packets = rdpcap(file_path)

for packet in packets:
    extract_credentials(packet)

