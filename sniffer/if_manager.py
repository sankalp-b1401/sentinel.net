from scapy.arch.windows import get_windows_if_list
from tabulate import tabulate
from psutil import net_if_stats

def get_usable_interfaces():
    # List of network interfaces scanned by NPCAP Drivers
    if_list = get_windows_if_list()

    # List of network interface stats using psutil
    if_stats = net_if_stats()

    # Preparing a filtered interface list
    usable_ifaces = []
    for iface in if_list:
        name = iface['name']

        # Skip loopback interfaces
        if "Loopback" in iface['description']:
            continue

        stats = if_stats.get(name)

        # Skip interfaces that are down
        if not stats or not stats.isup:
            continue

        usable_ifaces.append(iface)
    
    return usable_ifaces, if_stats

# Function to select an interface
def select_interface():
    usable_ifaces, if_stats = get_usable_interfaces()

    # Prepare data for tabulate
    table_data = []
    for idx, iface in enumerate(usable_ifaces, start=1):
        ips = ", ".join(iface['ips']) if iface['ips'] else "NA"
        mac = iface['mac'] if iface['mac'] else "NA"
        status = "Up" if if_stats[iface['name']].isup else "Down"
        
        table_data.append([
            idx,
            iface['name'],
            iface['description'],
            iface['index'],
            status,
            ips,
            mac
        ])

    # Display table
    headers = ["Idx", "Name", "Description", "SystemIdx", "Status", "IP(s)", "MAC"]
    print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))

    # User selects interface
    while True:
        try:
            user_choice = int(input(f"\nSelect an interface to sniff packets (1-{len(usable_ifaces)}): "))
            if 1 <= user_choice <= len(usable_ifaces):
                return usable_ifaces[user_choice - 1]
            else:
                print("Invalid selection. Try again.")
        except ValueError:
            print("Please enter a valid number.")
