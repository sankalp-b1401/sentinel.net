from scapy.all import rdpcap, Ether, IP, TCP, UDP
import json
import os

os.listdir("capture_logs")
pkt_choice = int(input("Enter the packet number to analyze (1-5): "))
packets = rdpcap("capture_logs/capture_pkt.pcap")

packets_json = []
for seq, pkt in enumerate(packets, start=1):
    pkt_meta = {}
    pkt_meta['timestamp'] = float(pkt.time)
    pkt_meta['length'] = int(len(pkt))
    pkt_meta['packet_id'] = seq
    pkt_meta['protocols'] = {}

    if pkt.haslayer(Ether):
        pkt_meta['protocols']['Ether'] = {
            'src_mac': pkt[Ether].src,
            'dst_mac': pkt[Ether].dst,
            'type': pkt[Ether].type
        }
    if pkt.haslayer(IP):
        pkt_meta['protocols']['IP'] = {
            'src_ip': pkt[IP].src,
            'dst_ip': pkt[IP].dst,
            'ttl': pkt[IP].ttl,
            'proto': pkt[IP].proto
        }
    if pkt.haslayer(TCP):
        pkt_meta['protocols']['TCP'] = {
            'sport': pkt[TCP].sport,
            'dport': pkt[TCP].dport,
            'flags': int(pkt[TCP].flags)
        }
    if pkt.haslayer(UDP):
        pkt_meta['protocols']['UDP'] = {
            'sport': pkt[UDP].sport,
            'dport': pkt[UDP].dport,
            'checksum': int(pkt[UDP].checksum)
        }

    packets_json.append(pkt_meta)

with open("../capture_logs/capture_pkt.json", "w") as json_file:
    json.dump(packets_json, json_file, indent=4)
