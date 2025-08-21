from scapy.all import sniff, wrpcap
from if_manager import select_interface
import time

def capture_packets():
    selected_interface = select_interface()
    packets = sniff(iface=selected_interface, count=5)
    filename = f"capture_logs/capture_{time.strftime("%Y%m%d_%H%M%S")}.pcap"
    wrpcap(filename, packets)