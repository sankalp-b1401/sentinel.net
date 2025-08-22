from scapy.all import rdpcap, Ether, IP, TCP, UDP
import json
import os

# scandir() is more efficient when you also need file stats()
# Returns an iterator to the directory entry
# Unlike listdir() here every entry is an object
# In listdir() a list of strings is returned
with os.scandir("capture_logs") as entries:
    files = [entry for entry in entries]

for idx, entry in enumerate(files, start=1):
        entry_size = entry.stat().st_size
        print(f"{idx}. {entry.name} - {entry_size/1024:.2f} KB")

pkt_choice = int(input("Enter the packet number to analyze (1-5): "))

packets = rdpcap(f"capture_logs/{files[pkt_choice - 1].name}")

def parse_to_json():
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
            }

        packets_json.append(pkt_meta)

    with open(f"parsed_logs/{os.path.splitext(files[pkt_choice - 1].name)[0]}.json", "w") as json_file:
        json.dump(packets_json, json_file, indent=4)

def flow_record():
    flow_record = []

    for pkt in packets:
        flow_table = {
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            "protocol": pkt[IP].proto,
            "src_port": pkt[TCP].sport if pkt.haslayer(TCP) else pkt[UDP].sport,
            "dst_port": pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport,
        }
