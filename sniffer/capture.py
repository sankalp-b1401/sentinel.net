from scapy.all import sniff, wrpcap
from if_manager import select_interface
import time

def capture_packets():
    selected_interface = select_interface()

    #for flow record prototype only capturing TCP and UDP packets
    packets = sniff(iface=selected_interface['name'], filter='tcp or udp', count=20)
    filename = f"capture_logs/capture_{time.strftime('%Y%m%d_%H%M%S')}.pcap"
    wrpcap(filename, packets)

if __name__ == "__main__":
    capture_packets()