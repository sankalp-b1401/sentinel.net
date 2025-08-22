from scapy.arch.windows import get_windows_if_list
from tabulate import tabulate
from psutil import net_if_stats

# ----------------------------
# Helper Functions
# ----------------------------

def get_all_interfaces():
    """Retrieve all interfaces from Windows NPCAP and their stats."""
    try:
        if_list = get_windows_if_list()
        if_stats = net_if_stats()
    except Exception as e:
        raise RuntimeError(f"Error retrieving interfaces: {e}")
    return if_list, if_stats

def filter_usable_interfaces(if_list, if_stats):
    """Filter out loopback interfaces and interfaces that are down."""
    usable_ifaces = []
    for iface in if_list:
        name = iface['name']
        if "Loopback" in iface['description']:
            continue
        stats = if_stats.get(name)
        if not stats or not stats.isup:
            continue
        usable_ifaces.append(iface)
    return usable_ifaces

def display_interfaces(interfaces, if_stats):
    """Display available interfaces in a table using tabulate."""
    table_data = []
    for idx, iface in enumerate(interfaces, start=1):
        ips = ", ".join(iface['ips']) if iface['ips'] else "NA"
        mac = iface['mac'] if iface['mac'] else "NA"
        status = "Up" if if_stats[iface['name']].isup else "Down"
        table_data.append([idx, iface['name'], iface['description'], iface['index'], status, ips, mac])
    
    headers = ["Idx", "Name", "Description", "SystemIdx", "Status", "IP(s)", "MAC"]
    print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))

def user_select_interface(usable_ifaces):
    """Prompt the user to select an interface."""
    while True:
        try:
            choice = int(input(f"\nSelect an interface to sniff packets (1-{len(usable_ifaces)}): "))
            if 1 <= choice <= len(usable_ifaces):
                return usable_ifaces[choice - 1]
            else:
                print("Invalid selection. Try again.")
        except ValueError:
            print("Please enter a valid number.")

# ----------------------------
# Main Interface Manager Functions
# ----------------------------

def get_usable_interfaces():
    """Return a list of usable interfaces along with their stats."""
    if_list, if_stats = get_all_interfaces()
    usable_ifaces = filter_usable_interfaces(if_list, if_stats)
    if not usable_ifaces:
        raise RuntimeError("No usable network interfaces found.")
    return usable_ifaces, if_stats

def select_interface():
    """
    Main function to list usable interfaces and prompt user selection.
    Returns the selected interface dictionary.
    """
    usable_ifaces, if_stats = get_usable_interfaces()
    display_interfaces(usable_ifaces, if_stats)
    return user_select_interface(usable_ifaces)

# ----------------------------
# Example Usage
# ----------------------------
# if __name__ == "__main__":
#     try:
#         iface = select_interface()
#         print(f"\nSelected Interface: {iface['name']} - {iface['description']}")
#     except Exception as e:
#         print(f"Error: {e}")
