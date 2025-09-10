# sniffer/if_manager.py
from __future__ import annotations
import sys
from tabulate import tabulate
from psutil import net_if_stats, net_if_addrs

# Cross-platform support for listing interfaces.
# On Windows scapy offers a helper get_windows_if_list (NPcap must be installed).
# On non-Windows platforms we use psutil which is cross-platform and provides addresses/stats.

try:
    # Windows-specific fast path: scapy's NPcap-backed helper.
    from scapy.arch.windows import get_windows_if_list
    def _list_ifaces():
        # get_windows_if_list() returns a list of dictionaries describing interfaces
        return get_windows_if_list()
except Exception:
    # Fallback for Linux/macOS using psutil to build a similar list of dicts.
    def _list_ifaces():
        out = []
        for name, addrs in net_if_addrs().items():
            # AF_INET and AF_INET6 are socket constants with fixed integer values
            # 2 -> AF_INET (IPv4), 23 -> AF_INET6 (IPv6)
            # We filter addresses to collect only IP addresses (IPv4/IPv6)
            ips = [a.address for a in addrs if getattr(a, "family", None) in (2, 23)]

            # AF_LINK is typically used for MAC addresses on BSD/macOS
            macs = [a.address for a in addrs if str(getattr(a, "family", "")) == "AF_LINK"]

            out.append({
                "name": name,
                "description": name,
                "index": None,       # system index may not be available here
                "ips": ips,
                "mac": macs[0] if macs else None,
            })
        return out

class InterfaceManager:
    """
    Helper to list, display and select network interfaces.

    Design notes:
    - refresh() collects interface metadata and stats.
    - usable() filters out loopback and down interfaces.
    - display() prints a nice table using tabulate.
    - select() is an interactive prompt to pick an interface.
    """

    def __init__(self) -> None:
        self._if_list = []
        self._if_stats = {}

    def refresh(self) -> None:
        """
        Populate self._if_list and self._if_stats.

        - _list_ifaces() returns a list of dicts describing interfaces.
        - net_if_stats() returns a dict of name -> stats namedtuple (isup, mtu, etc).
        """
        try:
            self._if_list = _list_ifaces()
            self._if_stats = net_if_stats()
        except Exception as e:
            raise RuntimeError(f"Error retrieving interfaces: {e}")

    def usable(self) -> list[dict]:
        """
        Return a list of interfaces that are likely usable for packet capture:
        - Excludes loopback interfaces (name starts with lo or description contains Loopback)
        - Excludes interfaces that are down (stats.isup is False)
        """
        self.refresh()
        usable = []
        for iface in self._if_list:
            name = iface.get("name", "")
            # Skip obvious loopback interfaces
            if "Loopback" in (iface.get("description") or "") or name.lower().startswith("lo"):
                continue
            stats = self._if_stats.get(name)
            # Skip interfaces with no stats or which are not up
            if not stats or not stats.isup:
                continue
            usable.append(iface)
        if not usable:
            # Let the caller know there are no usable NICs
            raise RuntimeError("No usable network interfaces found.")
        return usable

    def display(self, interfaces: list[dict]) -> None:
        """
        Nicely print a list of interfaces using tabulate with headers:
        Idx, Name, Description, SystemIdx, Status, IP(s), MAC
        """
        rows = []
        for idx, iface in enumerate(interfaces, start=1):
            name = iface.get("name", "NA")
            desc = iface.get("description", "NA")
            idx_sys = iface.get("index", "NA")
            ips = ", ".join(iface.get("ips") or []) or "NA"
            mac = iface.get("mac", "NA")
            status = "Up" if self._if_stats.get(name, None) and self._if_stats[name].isup else "Down"
            rows.append([idx, name, desc, idx_sys, status, ips, mac])
        # 'fancy_grid' makes a readable boxed table in terminals
        print(tabulate(rows, headers=["Idx","Name","Description","SystemIdx","Status","IP(s)","MAC"], tablefmt="fancy_grid"))

    def select(self) -> dict:
        """
        Interactive selection prompt.
        - Shows usable interfaces and asks the user to input an index.
        - Returns the selected interface dict.
        """
        interfaces = self.usable()
        self.display(interfaces)
        while True:
            try:
                choice = int(input(f"\nSelect interface (1-{len(interfaces)}): "))
                if 1 <= choice <= len(interfaces):
                    return interfaces[choice - 1]
            except ValueError:
                # Non-integer input -> fall through to invalid selection message below
                pass
            print("Invalid selection. Try again.")

if __name__ == "__main__":
    # CLI test: run interactive selection and print chosen interface name
    try:
        iface = InterfaceManager().select()
        print("\n[ok] Selected:", iface.get("name"))
    except Exception as e:
        print(f"[err] {e}")
        sys.exit(1)
