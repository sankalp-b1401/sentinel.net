from scapy.all import sniff, wrpcap
from if_manager import select_interface
import time
import os

# ----------------------------
# Helper Functions
# ----------------------------

def ensure_directory(directory):
    """Ensure the output directory exists."""
    os.makedirs(directory, exist_ok=True)
    return directory

def generate_filename(prefix="capture", output_dir="capture_logs"):
    """Generate a timestamped filename for the capture."""
    ensure_directory(output_dir)
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    return os.path.join(output_dir, f"{prefix}_{timestamp}.pcap")

def capture_packets_on_interface(interface_name, count=10000, bpf_filter='tcp or udp'):
    """Capture packets on the given interface."""
    try:
        print(f"Starting packet capture on interface: {interface_name}")
        packets = sniff(iface=interface_name, filter=bpf_filter, count=count)
        print(f"Captured {len(packets)} packets.")
        return packets
    except Exception as e:
        print(f"Error during packet capture: {e}")
        return []

def save_packets_to_file(packets, filename):
    """Save captured packets to a PCAP file."""
    if packets:
        try:
            wrpcap(filename, packets)
            print(f"Packets saved to {filename}")
        except Exception as e:
            print(f"Error saving packets to file: {e}")
    else:
        print("No packets to save.")

# ----------------------------
# Main Execution
# ----------------------------

def main():
    try:
        # Select the interface
        selected_interface = select_interface()
        if not selected_interface:
            print("No interface selected. Exiting.")
            return

        # Capture packets
        packets = capture_packets_on_interface(selected_interface['name'])

        # Save packets to file
        filename = generate_filename(prefix="capture")
        save_packets_to_file(packets, filename)

    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()