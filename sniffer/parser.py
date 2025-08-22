from scapy.all import rdpcap, Ether, IP, TCP, UDP
import json
import os

# ----------------------------
# Helper Functions
# ----------------------------

def list_capture_files(capture_dir="capture_logs"):
    """List PCAP files in capture directory with sizes."""
    try:
        with os.scandir(capture_dir) as entries:
            files = [entry for entry in entries if entry.is_file() and entry.name.endswith(".pcap")]
    except FileNotFoundError:
        raise FileNotFoundError(f"Directory '{capture_dir}' does not exist.")

    if not files:
        raise FileNotFoundError(f"No pcap files found in '{capture_dir}'.")

    for idx, entry in enumerate(files, start=1):
        entry_size = entry.stat().st_size
        print(f"{idx}. {entry.name} - {entry_size / 1024:.2f} KB")
    return files

def select_packet_file(files):
    """Prompt user to select a packet file."""
    while True:
        try:
            pkt_choice = int(input(f"Enter the packet number to analyze (1-{len(files)}): "))
            if 1 <= pkt_choice <= len(files):
                return files[pkt_choice - 1]
            else:
                print("Invalid selection. Try again.")
        except ValueError:
            print("Please enter a valid number.")

# ----------------------------
# Beta Parser Testing
# ----------------------------

def parse_to_json(packets, output_dir="parsed_logs", filename_prefix="parsed"):
    """Convert packets to per-packet JSON representation."""
    os.makedirs(output_dir, exist_ok=True)
    packets_json = []

    for seq, pkt in enumerate(packets, start=1):
        if IP not in pkt:
            continue  # skip non-IP packets

        pkt_meta = {
            'timestamp': float(pkt.time),
            'length': int(len(pkt)),
            'packet_id': seq,
            'protocols': {}
        }

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
                'dport': pkt[UDP].dport
            }

        packets_json.append(pkt_meta)

    json_path = os.path.join(output_dir, f"{filename_prefix}.json")
    with open(json_path, "w") as json_file:
        json.dump(packets_json, json_file, indent=4)
    print(f"Per-packet JSON saved to {json_path}")


# ----------------------------
# Flow Record Functions
# ----------------------------

def initialize_flow_instance(pkt):
    """Create a new flow instance dictionary."""
    instance = {
        'start_time': float(pkt.time),
        'end_time': float(pkt.time),
        'packet_count': 1,
        'byte_count': int(len(pkt)),
        'syn_count': 0,
        'ack_count': 0,
        'fin_count': 0,
        'rst_count': 0
    }

    # Initialize TCP flags if TCP layer exists
    if pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        if flags & 0x02: instance['syn_count'] = 1
        if flags & 0x10: instance['ack_count'] = 1
        if flags & 0x01: instance['fin_count'] = 1
        if flags & 0x04: instance['rst_count'] = 1
    return instance

def update_flow_instance(instance, pkt):
    """Update an existing flow instance with a new packet."""
    instance['packet_count'] += 1
    instance['byte_count'] += int(len(pkt))
    instance['end_time'] = float(pkt.time)

    if pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        if flags & 0x02: instance['syn_count'] += 1
        if flags & 0x10: instance['ack_count'] += 1
        if flags & 0x01: instance['fin_count'] += 1
        if flags & 0x04: instance['rst_count'] += 1

def generate_flow_records(packets, expiration_window=30):
    """
    Generate flow records with expiration.
    Each 5-tuple can have multiple instances separated by expiration_window (seconds).
    """
    flow_table = {}

    for pkt in packets:
        if IP not in pkt:
            continue  # skip non-IP packets

        # Define 5-tuple key
        flow_key = (
            pkt[IP].src,
            pkt[IP].dst,
            pkt[IP].proto,
            pkt[TCP].sport if pkt.haslayer(TCP) else pkt[UDP].sport,
            pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport
        )

        # If first packet of this flow_key
        if flow_key not in flow_table:
            flow_table[flow_key] = [initialize_flow_instance(pkt)]
        else:
            last_instance = flow_table[flow_key][-1]

            # Check for expiration
            if pkt.time - last_instance['end_time'] > expiration_window:
                # Start a new flow instance
                flow_table[flow_key].append(initialize_flow_instance(pkt))
            else:
                # Update existing instance
                update_flow_instance(last_instance, pkt)

    return flow_table

def flow_table_to_json(flow_table, output_dir="../flow_records", filename_prefix="flow"):
    """Convert flow_table dict to JSON-ready list and save to file."""
    os.makedirs(output_dir, exist_ok=True)
    json_ready_flows = []

    for key, instances in flow_table.items():
        src_ip, dst_ip, proto, sport, dport = key
        for inst in instances:
            entry = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": proto,
                "src_port": sport,
                "dst_port": dport,
                "avg_size": inst['byte_count'] / inst['packet_count'],
                **inst
            }
            json_ready_flows.append(entry)

    json_path = os.path.join(output_dir, f"{filename_prefix}_flow.json")
    with open(json_path, "w") as json_file:
        json.dump(json_ready_flows, json_file, indent=4)
    print(f"Flow JSON saved to {json_path}")


# ----------------------------
# Main Execution
# ----------------------------

if __name__ == "__main__":
    try:
        files = list_capture_files()
        selected_file = select_packet_file(files)
        packets = rdpcap(selected_file.path)

        # Modular parse to JSON
        # parse_to_json(packets, filename_prefix=os.path.splitext(selected_file.name)[0])

        # Generate flow records with expiration
        flows = generate_flow_records(packets, expiration_window=30)
        flow_table_to_json(flows, filename_prefix=os.path.splitext(selected_file.name)[0])

    except Exception as e:
        print(f"Error occurred: {e}")
