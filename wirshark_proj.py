from scapy.all import *
import matplotlib.pyplot as plt
import pandas as pd
from tabulate import tabulate

def analyze_packet(packet, dataframe):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            seq_num = packet[TCP].seq
            ack_num = packet[TCP].ack
            payload_len = len(packet[TCP].payload)

           

            # إضافة البيانات إلى DataFrame
            data = {'Source IP': src_ip, 'Source Port': src_port, 'Destination IP': dst_ip,
                    'Destination Port': dst_port, 'Sequence Number': seq_num,
                    'Acknowledgment Number': ack_num, 'Payload Length': payload_len}
            dataframe = dataframe._append(data, ignore_index=True)
    return dataframe

# افتح ملف pcap
pcap_file = '/home/batool/Documents/GitHub/wireshark/b.pcapng'

# اقرأ حزم الشبكة من الملف
packets = rdpcap(pcap_file)

# إنشاء DataFrame لتخزين البيانات
packet_data = pd.DataFrame(columns=['Source IP', 'Source Port', 'Destination IP', 'Destination Port',
                                    'Sequence Number', 'Acknowledgment Number', 'Payload Length'])

# قم بتحليل كل حزمة وطباعة المعلومات
for packet in packets:
    packet_data = analyze_packet(packet, packet_data)

# عرض البيانات كجدول في التيرمينال
print(tabulate(packet_data, headers='keys', tablefmt='fancy_grid'))

# رسم بياني باستخدام matplotlib
plt.figure(figsize=(10, 6))
plt.plot(packet_data['Payload Length'], label='Payload Length')
plt.title('Payload Length in Each Packet')
plt.xlabel('Packet Index')
plt.ylabel('Payload Length (bytes)')
plt.legend()
plt.show()
